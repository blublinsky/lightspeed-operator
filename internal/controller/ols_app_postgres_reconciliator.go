package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cnpgv1 "github.com/cloudnative-pg/api/pkg/api/v1"
	olsv1alpha1 "github.com/openshift/lightspeed-operator/api/v1alpha1"
)

func (r *OLSConfigReconciler) reconcilePostgresServer(ctx context.Context, olsconfig *olsv1alpha1.OLSConfig) error {
	r.logger.Info("reconcilePostgresServer starts")

	// Validate certificate secret exists and is valid
	err := r.validatePostgresCertificateSecret(ctx, PostgresCertsSecretName)
	if err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	tasks := []ReconcileTask{
		{
			Name: "reconcile Postgres Secret",
			Task: r.reconcilePostgresSecret,
		},
		{
			Name: "reconcile Postgres Service",
			Task: r.reconcilePostgresService,
		},
		{
			Name: "reconcile CloudNativePG Cluster",
			Task: r.reconcileCloudNativePGCluster,
		},
		{
			Name: "generate Postgres Network Policy",
			Task: r.reconcilePostgresNetworkPolicy,
		},
	}

	for _, task := range tasks {
		err := task.Task(ctx, olsconfig)
		if err != nil {
			r.logger.Error(err, "reconcilePostgresServer error", "task", task.Name)
			return fmt.Errorf("failed to %s: %w", task.Name, err)
		}
	}

	r.logger.Info("reconcilePostgresServer completed")

	return nil
}

func (r *OLSConfigReconciler) reconcilePostgresService(ctx context.Context, cr *olsv1alpha1.OLSConfig) error {
	service, err := r.generatePostgresService(cr)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresService, err)
	}

	foundService := &corev1.Service{}
	err = r.Get(ctx, client.ObjectKey{Name: PostgresServiceName, Namespace: r.Options.Namespace}, foundService)
	if err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, service)
		if err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresService, err)
		}
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresService, err)
	}
	r.logger.Info("OLS postgres service reconciled", "service", service.Name)
	return nil
}

func (r *OLSConfigReconciler) reconcilePostgresSecret(ctx context.Context, cr *olsv1alpha1.OLSConfig) error {
	secret, err := r.generatePostgresSecret(cr)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresSecret, err)
	}
	foundSecret := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKey{Name: secret.Name, Namespace: r.Options.Namespace}, foundSecret)
	if err != nil && errors.IsNotFound(err) {
		err = r.deleteOldPostgresSecrets(ctx)
		if err != nil {
			return err
		}
		r.logger.Info("creating a new Postgres secret", "secret", secret.Name)
		err = r.Create(ctx, secret)
		if err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresSecret, err)
		}
		r.stateCache[PostgresSecretHashStateCacheKey] = secret.Annotations[PostgresSecretHashKey]
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresSecret, err)
	}
	foundSecretHash, err := hashBytes(foundSecret.Data[PostgresSecretKeyName])
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresSecretHash, err)
	}
	if foundSecretHash == r.stateCache[PostgresSecretHashStateCacheKey] {
		r.logger.Info("OLS postgres secret reconciliation skipped", "secret", foundSecret.Name, "hash", foundSecret.Annotations[PostgresSecretHashKey])
		return nil
	}
	r.stateCache[PostgresSecretHashStateCacheKey] = foundSecretHash
	secret.Annotations[PostgresSecretHashKey] = foundSecretHash
	secret.Data[PostgresSecretKeyName] = foundSecret.Data[PostgresSecretKeyName]
	err = r.Update(ctx, secret)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrUpdatePostgresSecret, err)
	}
	r.logger.Info("OLS postgres reconciled", "secret", secret.Name, "hash", secret.Annotations[PostgresSecretHashKey])
	return nil
}

func (r *OLSConfigReconciler) deleteOldPostgresSecrets(ctx context.Context) error {
	labelSelector := labels.Set{"app.kubernetes.io/name": "lightspeed-service-postgres"}.AsSelector()
	matchingLabels := client.MatchingLabelsSelector{Selector: labelSelector}
	oldSecrets := &corev1.SecretList{}
	err := r.List(ctx, oldSecrets, &client.ListOptions{Namespace: r.Options.Namespace, LabelSelector: labelSelector})
	if err != nil {
		return fmt.Errorf("failed to list old Postgres secrets: %w", err)
	}
	r.logger.Info("deleting old Postgres secrets", "count", len(oldSecrets.Items))

	deleteOptions := &client.DeleteAllOfOptions{
		ListOptions: client.ListOptions{
			Namespace:     r.Options.Namespace,
			LabelSelector: matchingLabels,
		},
	}
	if err := r.DeleteAllOf(ctx, &corev1.Secret{}, deleteOptions); err != nil {
		return fmt.Errorf("failed to delete old Postgres secrets: %w", err)
	}
	return nil
}

func (r *OLSConfigReconciler) reconcilePostgresNetworkPolicy(ctx context.Context, cr *olsv1alpha1.OLSConfig) error {
	networkPolicy, err := r.generatePostgresNetworkPolicy(cr)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresNetworkPolicy, err)
	}
	foundNetworkPolicy := &networkingv1.NetworkPolicy{}
	err = r.Get(ctx, client.ObjectKey{Name: PostgresNetworkPolicyName, Namespace: r.Options.Namespace}, foundNetworkPolicy)
	if err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, networkPolicy)
		if err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresNetworkPolicy, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresNetworkPolicy, err)
	}
	if networkPolicyEqual(foundNetworkPolicy, networkPolicy) {
		r.logger.Info("OLS postgres network policy unchanged, reconciliation skipped", "network policy", networkPolicy.Name)
		return nil
	}
	foundNetworkPolicy.Spec = networkPolicy.Spec
	err = r.Update(ctx, foundNetworkPolicy)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrUpdatePostgresNetworkPolicy, err)
	}
	r.logger.Info("OLS postgres network policy reconciled", "network policy", networkPolicy.Name)
	return nil
}

// reconcileCloudNativePGCluster reconciles the CloudNativePG cluster
func (r *OLSConfigReconciler) reconcileCloudNativePGCluster(ctx context.Context, cr *olsv1alpha1.OLSConfig) error {
	desiredCluster, err := r.generateCloudNativePGCluster(cr)
	if err != nil {
		return fmt.Errorf("failed to generate CloudNativePG cluster: %w", err)
	}

	existingCluster := &cnpgv1.Cluster{}
	err = r.Get(ctx, client.ObjectKey{
		Name:      "lightspeed-postgres-cluster",
		Namespace: r.Options.Namespace,
	}, existingCluster)

	if err != nil && errors.IsNotFound(err) {
		r.logger.Info("creating CloudNativePG cluster", "cluster", desiredCluster.Name)
		err = r.Create(ctx, desiredCluster)
		if err != nil {
			return fmt.Errorf("failed to create CloudNativePG cluster: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get CloudNativePG cluster: %w", err)
	}

	// Update cluster if needed
	err = r.updateCloudNativePGCluster(ctx, existingCluster, desiredCluster)
	if err != nil {
		return fmt.Errorf("failed to update CloudNativePG cluster: %w", err)
	}

	r.logger.Info("CloudNativePG cluster reconciled", "cluster", desiredCluster.Name)
	return nil
}

// validatePostgresCertificateSecret validates that the PostgreSQL certificate secret exists and is valid
func (r *OLSConfigReconciler) validatePostgresCertificateSecret(ctx context.Context, secretName string) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      secretName,
		Namespace: r.Options.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("certificate secret %s not found - ensure OpenShift Service CA has generated it", secretName)
		}
		return fmt.Errorf("failed to get certificate secret %s: %w", secretName, err)
	}

	// Validate required keys exist
	requiredKeys := []string{"tls.crt", "tls.key"}
	for _, key := range requiredKeys {
		if _, exists := secret.Data[key]; !exists {
			return fmt.Errorf("required key %s not found in secret %s", key, secretName)
		}
	}

	// Validate certificate format and expiration
	certPEM := secret.Data["tls.crt"]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate in secret %s", secretName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate in secret %s: %w", secretName, err)
	}

	// Check certificate expiration (warn if less than 30 days)
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		r.logger.Info("PostgreSQL certificate expires soon",
			"secret", secretName,
			"expiry", cert.NotAfter,
			"days_remaining", int(time.Until(cert.NotAfter).Hours()/24))
	}

	r.logger.Info("PostgreSQL certificate validation successful",
		"secret", secretName,
		"subject", cert.Subject.CommonName,
		"expiry", cert.NotAfter)

	return nil
}
