package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cnpgv1 "github.com/cloudnative-pg/api/pkg/api/v1"
	olsv1alpha1 "github.com/openshift/lightspeed-operator/api/v1alpha1"
)

func generatePostgresSelectorLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/component":  "postgres-server",
		"app.kubernetes.io/managed-by": "lightspeed-operator",
		"app.kubernetes.io/name":       "lightspeed-service-postgres",
		"app.kubernetes.io/part-of":    "openshift-lightspeed",
	}
}

func getPostgresCAConfigVolume() corev1.Volume {
	return corev1.Volume{
		Name: PostgresCAVolume,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: OLSCAConfigMap,
				},
			},
		},
	}
}

func getPostgresCAVolumeMount(mountPath string) corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      PostgresCAVolume,
		MountPath: mountPath,
		ReadOnly:  true,
	}
}

func (r *OLSConfigReconciler) generatePostgresDeployment(cr *olsv1alpha1.OLSConfig) (*appsv1.Deployment, error) {
	cacheReplicas := int32(1)
	revisionHistoryLimit := int32(1)
	postgresSecretName := PostgresSecretName
	if cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret != "" {
		postgresSecretName = cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret
	}

	passwordMap, err := getSecretContent(r.Client, postgresSecretName, r.Options.Namespace, []string{OLSComponentPasswordFileName}, &corev1.Secret{})
	if err != nil {
		return nil, fmt.Errorf("password is needed to start postgres deployment : %w", err)
	}
	postgresPassword := passwordMap[OLSComponentPasswordFileName]
	if cr.Spec.OLSConfig.ConversationCache.Postgres.SharedBuffers == "" {
		cr.Spec.OLSConfig.ConversationCache.Postgres.SharedBuffers = PostgresSharedBuffers
	}
	if cr.Spec.OLSConfig.ConversationCache.Postgres.MaxConnections == 0 {
		cr.Spec.OLSConfig.ConversationCache.Postgres.MaxConnections = PostgresMaxConnections
	}
	defaultPermission := int32(0600)
	tlsCertsVolume := corev1.Volume{
		Name: "secret-" + PostgresCertsSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  PostgresCertsSecretName,
				DefaultMode: &defaultPermission,
			},
		},
	}
	bootstrapVolume := corev1.Volume{
		Name: "secret-" + PostgresBootstrapSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: PostgresBootstrapSecretName,
			},
		},
	}
	configVolume := corev1.Volume{
		Name: PostgresConfigMap,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: PostgresConfigMap},
			},
		},
	}

	dataVolume := corev1.Volume{
		Name: PostgresDataVolume,
	}
	if cr.Spec.OLSConfig.Storage != nil {
		dataVolume.VolumeSource = corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: PostgresPVCName,
			},
		}
	} else {
		dataVolume.VolumeSource = corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		}
	}

	varRunVolume := corev1.Volume{
		Name: PostgresVarRunVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	tmpVolume := corev1.Volume{
		Name: TmpVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	volumes := []corev1.Volume{tlsCertsVolume, bootstrapVolume, configVolume, dataVolume, getPostgresCAConfigVolume(), varRunVolume, tmpVolume}
	postgresTLSVolumeMount := corev1.VolumeMount{
		Name:      "secret-" + PostgresCertsSecretName,
		MountPath: OLSAppCertsMountRoot,
		ReadOnly:  true,
	}
	bootstrapVolumeMount := corev1.VolumeMount{
		Name:      "secret-" + PostgresBootstrapSecretName,
		MountPath: PostgresBootstrapVolumeMountPath,
		SubPath:   PostgresExtensionScript,
		ReadOnly:  true,
	}
	configVolumeMount := corev1.VolumeMount{
		Name:      PostgresConfigMap,
		MountPath: PostgresConfigVolumeMountPath,
		SubPath:   PostgresConfig,
	}
	dataVolumeMount := corev1.VolumeMount{
		Name:      PostgresDataVolume,
		MountPath: PostgresDataVolumeMountPath,
	}
	varRunVolumeMount := corev1.VolumeMount{
		Name:      PostgresVarRunVolumeName,
		MountPath: PostgresVarRunVolumeMountPath,
	}
	tmpVolumeMount := corev1.VolumeMount{
		Name:      TmpVolumeName,
		MountPath: TmpVolumeMountPath,
	}

	volumeMounts := []corev1.VolumeMount{
		postgresTLSVolumeMount,
		bootstrapVolumeMount,
		configVolumeMount,
		dataVolumeMount,
		getPostgresCAVolumeMount(path.Join(OLSAppCertsMountRoot, PostgresCAVolume)),
		varRunVolumeMount,
		tmpVolumeMount,
	}

	databaseResources := getDatabaseResources(cr)

	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresDeploymentName,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &cacheReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: generatePostgresSelectorLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: generatePostgresSelectorLabels(),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            PostgresDeploymentName,
							Image:           r.Options.LightspeedServicePostgresImage,
							ImagePullPolicy: corev1.PullAlways,
							Ports: []corev1.ContainerPort{
								{
									Name:          "server",
									ContainerPort: PostgresServicePort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								ReadOnlyRootFilesystem:   &[]bool{true}[0],
							},
							VolumeMounts: volumeMounts,
							Resources:    *databaseResources,
							Env: []corev1.EnvVar{
								{
									Name:  "POSTGRESQL_USER",
									Value: PostgresDefaultUser,
								},
								{
									Name:  "POSTGRESQL_DATABASE",
									Value: PostgresDefaultDbName,
								},
								{
									Name:  "POSTGRESQL_ADMIN_PASSWORD",
									Value: postgresPassword,
								},
								{
									Name:  "POSTGRESQL_PASSWORD",
									Value: postgresPassword,
								},
								{
									Name:  "POSTGRESQL_SHARED_BUFFERS",
									Value: cr.Spec.OLSConfig.ConversationCache.Postgres.SharedBuffers,
								},
								{
									Name:  "POSTGRESQL_MAX_CONNECTIONS",
									Value: strconv.Itoa(cr.Spec.OLSConfig.ConversationCache.Postgres.MaxConnections),
								},
							},
						},
					},
					Volumes: volumes,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
		},
	}

	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Tolerations != nil {
		deployment.Spec.Template.Spec.Tolerations = cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Tolerations
	}
	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.NodeSelector != nil {
		deployment.Spec.Template.Spec.NodeSelector = cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.NodeSelector
	}
	if err := controllerutil.SetControllerReference(cr, &deployment, r.Scheme); err != nil {
		return nil, err
	}

	return &deployment, nil
}

// updatePostgresDeployment updates the deployment based on CustomResource configuration.
func (r *OLSConfigReconciler) updatePostgresDeployment(ctx context.Context, existingDeployment, desiredDeployment *appsv1.Deployment) error {
	changed := false

	// Validate deployment annotations.
	if existingDeployment.Annotations == nil ||
		existingDeployment.Annotations[PostgresConfigHashKey] != r.stateCache[PostgresConfigHashStateCacheKey] ||
		existingDeployment.Annotations[PostgresSecretHashKey] != r.stateCache[PostgresSecretHashStateCacheKey] {
		updateDeploymentAnnotations(existingDeployment, map[string]string{
			PostgresConfigHashKey: r.stateCache[PostgresConfigHashStateCacheKey],
			PostgresSecretHashKey: r.stateCache[PostgresSecretHashStateCacheKey],
		})
		// update the deployment template annotation triggers the rolling update
		updateDeploymentTemplateAnnotations(existingDeployment, map[string]string{
			PostgresConfigHashKey: r.stateCache[PostgresConfigHashStateCacheKey],
			PostgresSecretHashKey: r.stateCache[PostgresSecretHashStateCacheKey],
		})

		if _, err := setDeploymentContainerEnvs(existingDeployment, desiredDeployment.Spec.Template.Spec.Containers[0].Env, PostgresDeploymentName); err != nil {
			return err
		}

		changed = true
	}

	if changed {
		r.logger.Info("updating OLS postgres deployment", "name", existingDeployment.Name)
		if err := r.Update(ctx, existingDeployment); err != nil {
			return err
		}
	} else {
		r.logger.Info("OLS postgres deployment reconciliation skipped", "deployment", existingDeployment.Name, "olsconfig hash", existingDeployment.Annotations[PostgresConfigHashKey])
	}

	return nil
}

func (r *OLSConfigReconciler) generatePostgresService(cr *olsv1alpha1.OLSConfig) (*corev1.Service, error) {
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresServiceName,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
			Annotations: map[string]string{
				ServingCertSecretAnnotationKey: PostgresCertsSecretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       PostgresServicePort,
					Protocol:   corev1.ProtocolTCP,
					Name:       "server",
					TargetPort: intstr.Parse("server"),
				},
			},
			Selector: generatePostgresSelectorLabels(),
			Type:     corev1.ServiceTypeClusterIP,
		},
	}

	if err := controllerutil.SetControllerReference(cr, &service, r.Scheme); err != nil {
		return nil, err
	}

	return &service, nil
}

func (r *OLSConfigReconciler) generatePostgresSecret(cr *olsv1alpha1.OLSConfig) (*corev1.Secret, error) {
	postgresSecretName := PostgresSecretName
	if cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret != "" {
		postgresSecretName = cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret
	}
	randomPassword := make([]byte, 12)
	_, err := rand.Read(randomPassword)
	if err != nil {
		return nil, fmt.Errorf("error generating random password: %w", err)
	}
	// Encode the password to base64
	encodedPassword := base64.StdEncoding.EncodeToString(randomPassword)
	passwordHash, err := hashBytes([]byte(encodedPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to generate OLS postgres password hash %w", err)
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      postgresSecretName,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
			Annotations: map[string]string{
				PostgresSecretHashKey: passwordHash,
			},
		},
		Data: map[string][]byte{
			PostgresSecretKeyName: []byte(encodedPassword),
		},
	}

	if err := controllerutil.SetControllerReference(cr, &secret, r.Scheme); err != nil {
		return nil, err
	}

	return &secret, nil
}

func (r *OLSConfigReconciler) generatePostgresBootstrapSecret(cr *olsv1alpha1.OLSConfig) (*corev1.Secret, error) {
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresBootstrapSecretName,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
		},
		StringData: map[string]string{
			PostgresExtensionScript: string(PostgresBootStrapScriptContent),
		},
	}

	if err := controllerutil.SetControllerReference(cr, &secret, r.Scheme); err != nil {
		return nil, err
	}

	return &secret, nil
}

func (r *OLSConfigReconciler) generatePostgresConfigMap(cr *olsv1alpha1.OLSConfig) (*corev1.ConfigMap, error) {
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresConfigMap,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
		},
		Data: map[string]string{
			PostgresConfig: PostgresConfigMapContent,
		},
	}

	if err := controllerutil.SetControllerReference(cr, &configMap, r.Scheme); err != nil {
		return nil, err
	}

	return &configMap, nil
}

func (r *OLSConfigReconciler) generatePostgresNetworkPolicy(cr *olsv1alpha1.OLSConfig) (*networkingv1.NetworkPolicy, error) {
	np := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresNetworkPolicyName,
			Namespace: r.Options.Namespace,
			Labels:    generatePostgresSelectorLabels(),
		},
		Spec: networkingv1.NetworkPolicySpec{
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: generateAppServerSelectorLabels(),
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
							Port:     &[]intstr.IntOrString{intstr.FromInt(PostgresServicePort)}[0],
						},
					},
				},
			},
			PodSelector: metav1.LabelSelector{
				MatchLabels: generatePostgresSelectorLabels(),
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
	if err := controllerutil.SetControllerReference(cr, &np, r.Scheme); err != nil {
		return nil, err
	}
	return &np, nil
}

func getDatabaseResources(cr *olsv1alpha1.OLSConfig) *corev1.ResourceRequirements {
	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Resources != nil {
		return cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Resources
	}
	defaultResources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("30m"),
			corev1.ResourceMemory: resource.MustParse("300Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}

	return defaultResources
}

// generateCloudNativePGCluster creates a CloudNativePG Cluster resource
func (r *OLSConfigReconciler) generateCloudNativePGCluster(cr *olsv1alpha1.OLSConfig) (*cnpgv1.Cluster, error) {
	// Set default values
	instances := 2 // Primary + 1 standby for HA

	// Get PostgreSQL configuration
	postgresConfig := cr.Spec.OLSConfig.ConversationCache.Postgres

	// Set defaults for missing values
	if postgresConfig.User == "" {
		postgresConfig.User = PostgresDefaultUser
	}
	if postgresConfig.DbName == "" {
		postgresConfig.DbName = PostgresDefaultDbName
	}
	if postgresConfig.CredentialsSecret == "" {
		postgresConfig.CredentialsSecret = PostgresSecretName
	}
	if postgresConfig.SharedBuffers == "" {
		postgresConfig.SharedBuffers = PostgresSharedBuffers
	}
	if postgresConfig.MaxConnections == 0 {
		postgresConfig.MaxConnections = PostgresMaxConnections
	}

	// Create CloudNativePG Cluster
	cluster := &cnpgv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lightspeed-postgres-cluster",
			Namespace: r.Options.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/component":  "postgres-server",
				"app.kubernetes.io/managed-by": "lightspeed-operator",
				"app.kubernetes.io/name":       "lightspeed-service-postgres",
				"app.kubernetes.io/part-of":    "openshift-lightspeed",
			},
		},
		Spec: cnpgv1.ClusterSpec{
			Instances: instances,
			PostgresConfiguration: cnpgv1.PostgresConfiguration{
				Parameters: map[string]string{
					"ssl":             "on",
					"shared_buffers":  postgresConfig.SharedBuffers,
					"max_connections": strconv.Itoa(postgresConfig.MaxConnections),
				},
			},
			Bootstrap: &cnpgv1.BootstrapConfiguration{
				InitDB: &cnpgv1.BootstrapInitDB{
					Database: postgresConfig.DbName,
					Owner:    postgresConfig.User,
					Secret: &cnpgv1.LocalObjectReference{
						Name: postgresConfig.CredentialsSecret,
					},
				},
			},
			StorageConfiguration: cnpgv1.StorageConfiguration{
				Size:         getStorageSizeString(cr),
				StorageClass: getStorageClass(cr),
			},
			// Use custom certificate secret
			Certificates: &cnpgv1.CertificatesConfiguration{
				ServerTLSSecret: PostgresCertsSecretName,
			},
		},
	}

	// Add resource requirements if specified
	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Resources != nil {
		cluster.Spec.Resources = *cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Resources
	} else {
		// Set default resources
		cluster.Spec.Resources = corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("30m"),
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("2Gi"),
			},
		}
	}

	// Add node selector if specified
	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.NodeSelector != nil {
		cluster.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"linux"},
							},
						},
					},
				},
			},
		}
	}

	// Add tolerations if specified
	if cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Tolerations != nil {
		// CloudNativePG doesn't have direct tolerations field, we'll need to use affinity
		// For now, we'll skip this as it requires more complex configuration
	}

	// Set controller reference
	if err := controllerutil.SetControllerReference(cr, cluster, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	return cluster, nil
}

// getStorageSizeString returns the storage size as a string from the OLSConfig or default
func getStorageSizeString(cr *olsv1alpha1.OLSConfig) string {
	if cr.Spec.OLSConfig.Storage != nil && !cr.Spec.OLSConfig.Storage.Size.IsZero() {
		return cr.Spec.OLSConfig.Storage.Size.String()
	}
	return PostgresDefaultPVCSize
}

// getStorageClass returns the storage class from the OLSConfig or nil
func getStorageClass(cr *olsv1alpha1.OLSConfig) *string {
	if cr.Spec.OLSConfig.Storage != nil && cr.Spec.OLSConfig.Storage.Class != "" {
		return &cr.Spec.OLSConfig.Storage.Class
	}
	return nil
}

// updateCloudNativePGCluster updates an existing CloudNativePG cluster
func (r *OLSConfigReconciler) updateCloudNativePGCluster(ctx context.Context, existingCluster, desiredCluster *cnpgv1.Cluster) error {
	changed := false

	// Check if PostgreSQL parameters changed
	if !mapsEqual(existingCluster.Spec.PostgresConfiguration.Parameters, desiredCluster.Spec.PostgresConfiguration.Parameters) {
		existingCluster.Spec.PostgresConfiguration.Parameters = desiredCluster.Spec.PostgresConfiguration.Parameters
		changed = true
	}

	// Check if instances changed
	if existingCluster.Spec.Instances != desiredCluster.Spec.Instances {
		existingCluster.Spec.Instances = desiredCluster.Spec.Instances
		changed = true
	}

	// Check if resources changed
	if !resourceRequirementsEqual(existingCluster.Spec.Resources, desiredCluster.Spec.Resources) {
		existingCluster.Spec.Resources = desiredCluster.Spec.Resources
		changed = true
	}

	// Check if storage changed
	if !storageConfigurationEqual(existingCluster.Spec.StorageConfiguration, desiredCluster.Spec.StorageConfiguration) {
		existingCluster.Spec.StorageConfiguration = desiredCluster.Spec.StorageConfiguration
		changed = true
	}

	if changed {
		r.logger.Info("updating CloudNativePG cluster", "name", existingCluster.Name)
		if err := r.Update(ctx, existingCluster); err != nil {
			return fmt.Errorf("failed to update CloudNativePG cluster: %w", err)
		}
	} else {
		r.logger.Info("CloudNativePG cluster reconciliation skipped", "cluster", existingCluster.Name)
	}

	return nil
}

// Helper functions for comparison
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func resourceRequirementsEqual(a, b corev1.ResourceRequirements) bool {
	return resourceListEqual(a.Requests, b.Requests) && resourceListEqual(a.Limits, b.Limits)
}

func resourceListEqual(a, b corev1.ResourceList) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !v.Equal(b[k]) {
			return false
		}
	}
	return true
}

func storageConfigurationEqual(a, b cnpgv1.StorageConfiguration) bool {
	return a.Size == b.Size &&
		((a.StorageClass == nil && b.StorageClass == nil) ||
			(a.StorageClass != nil && b.StorageClass != nil && *a.StorageClass == *b.StorageClass))
}
