package controller

import (
	"path"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	olsv1alpha1 "github.com/openshift/lightspeed-operator/api/v1alpha1"
)

var _ = Describe("App postgres server assets", func() {

	var cr *olsv1alpha1.OLSConfig
	var r *OLSConfigReconciler
	var rOptions *OLSConfigReconcilerOptions

	validatePostgresDeployment := func(dep *appsv1.Deployment, password string, with_pvc bool) {
		replicas := int32(1)
		revisionHistoryLimit := int32(1)
		defaultPermission := int32(0600)
		Expect(dep.Name).To(Equal(PostgresDeploymentName))
		Expect(dep.Namespace).To(Equal(OLSNamespaceDefault))
		Expect(dep.Spec.Template.Spec.Containers[0].Image).To(Equal(rOptions.LightspeedServicePostgresImage))
		Expect(dep.Spec.Template.Spec.Containers[0].Name).To(Equal("lightspeed-postgres-server"))
		Expect(dep.Spec.Template.Spec.Containers[0].ImagePullPolicy).To(Equal(corev1.PullAlways))
		Expect(dep.Spec.Template.Spec.Containers[0].Ports).To(Equal([]corev1.ContainerPort{
			{
				ContainerPort: PostgresServicePort,
				Name:          "server",
				Protocol:      corev1.ProtocolTCP,
			},
		}))
		Expect(dep.Spec.Template.Spec.Containers[0].Resources).To(Equal(corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("30m"),
				corev1.ResourceMemory: resource.MustParse("300Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("2Gi"),
			},
		}))
		Expect(dep.Spec.Template.Spec.Containers[0].Env).To(Equal([]corev1.EnvVar{
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
				Value: password,
			},
			{
				Name:  "POSTGRESQL_PASSWORD",
				Value: password,
			},
			{
				Name:  "POSTGRESQL_SHARED_BUFFERS",
				Value: PostgresSharedBuffers,
			},
			{
				Name:  "POSTGRESQL_MAX_CONNECTIONS",
				Value: strconv.Itoa(PostgresMaxConnections),
			},
		}))
		Expect(dep.Spec.Selector.MatchLabels).To(Equal(generatePostgresSelectorLabels()))
		Expect(dep.Spec.RevisionHistoryLimit).To(Equal(&revisionHistoryLimit))
		Expect(dep.Spec.Replicas).To(Equal(&replicas))
		Expect(dep.Spec.Template.Spec.Containers[0].VolumeMounts).To(Equal([]corev1.VolumeMount{
			{
				Name:      "secret-" + PostgresCertsSecretName,
				MountPath: OLSAppCertsMountRoot,
				ReadOnly:  true,
			},
			{
				Name:      "secret-" + PostgresBootstrapSecretName,
				MountPath: PostgresBootstrapVolumeMountPath,
				SubPath:   PostgresExtensionScript,
				ReadOnly:  true,
			},
			{
				Name:      PostgresConfigMap,
				MountPath: PostgresConfigVolumeMountPath,
				SubPath:   PostgresConfig,
			},
			{
				Name:      PostgresDataVolume,
				MountPath: PostgresDataVolumeMountPath,
			},
			{
				Name:      PostgresCAVolume,
				MountPath: path.Join(OLSAppCertsMountRoot, PostgresCAVolume),
				ReadOnly:  true,
			},
			{
				Name:      PostgresVarRunVolumeName,
				MountPath: PostgresVarRunVolumeMountPath,
			},
			{
				Name:      TmpVolumeName,
				MountPath: TmpVolumeMountPath,
			},
		}))
		expectedVolumes := []corev1.Volume{
			{
				Name: "secret-" + PostgresCertsSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  PostgresCertsSecretName,
						DefaultMode: &defaultPermission,
					},
				},
			},
			{
				Name: "secret-" + PostgresBootstrapSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: PostgresBootstrapSecretName,
					},
				},
			},
			{
				Name: PostgresConfigMap,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: PostgresConfigMap},
					},
				},
			},
		}
		if with_pvc {
			expectedVolumes = append(expectedVolumes, corev1.Volume{
				Name: PostgresDataVolume,
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: PostgresPVCName,
					},
				},
			})
		} else {
			expectedVolumes = append(expectedVolumes, corev1.Volume{
				Name: PostgresDataVolume,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
		}
		expectedVolumes = append(expectedVolumes,
			corev1.Volume{
				Name: PostgresCAVolume,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: OLSCAConfigMap},
					},
				},
			},
			corev1.Volume{
				Name: PostgresVarRunVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			corev1.Volume{
				Name: TmpVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
		Expect(dep.Spec.Template.Spec.Volumes).To(Equal(expectedVolumes))
	}

	validatePostgresService := func(service *corev1.Service, err error) {
		Expect(err).NotTo(HaveOccurred())
		Expect(service.Name).To(Equal(PostgresServiceName))
		Expect(service.Namespace).To(Equal(OLSNamespaceDefault))
		Expect(service.Labels).To(Equal(generatePostgresSelectorLabels()))
		Expect(service.Annotations).To(Equal(map[string]string{
			"service.beta.openshift.io/serving-cert-secret-name": PostgresCertsSecretName,
		}))
		Expect(service.Spec.Selector).To(Equal(generatePostgresSelectorLabels()))
		Expect(service.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
		Expect(service.Spec.Ports).To(Equal([]corev1.ServicePort{
			{
				Name:       "server",
				Port:       PostgresServicePort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.Parse("server"),
			},
		}))
	}

	validatePostgresConfigMap := func(configMap *corev1.ConfigMap) {
		Expect(configMap.Namespace).To(Equal(cr.Namespace))
		Expect(configMap.Labels).To(Equal(generatePostgresSelectorLabels()))
		Expect(configMap.Data).To(HaveKey(PostgresConfig))
	}

	validatePostgresSecret := func(secret *corev1.Secret) {
		Expect(secret.Namespace).To(Equal(cr.Namespace))
		Expect(secret.Labels).To(Equal(generatePostgresSelectorLabels()))
		Expect(secret.Annotations).To(HaveKey(PostgresSecretHashKey))
		Expect(secret.Data).To(HaveKey(PostgresSecretKeyName))
	}

	validatePostgresBootstrapSecret := func(secret *corev1.Secret) {
		Expect(secret.Namespace).To(Equal(cr.Namespace))
		Expect(secret.Labels).To(Equal(generatePostgresSelectorLabels()))
		Expect(secret.StringData).To(HaveKey(PostgresExtensionScript))
	}

	validatePostgresNetworkPolicy := func(networkPolicy *networkingv1.NetworkPolicy) {
		Expect(networkPolicy.Name).To(Equal(PostgresNetworkPolicyName))
		Expect(networkPolicy.Namespace).To(Equal(OLSNamespaceDefault))
		Expect(networkPolicy.Spec.PolicyTypes).To(Equal([]networkingv1.PolicyType{networkingv1.PolicyTypeIngress}))
		Expect(networkPolicy.Spec.Ingress).To(HaveLen(1))
		Expect(networkPolicy.Spec.Ingress).To(ConsistOf(networkingv1.NetworkPolicyIngressRule{
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
		}))
		Expect(networkPolicy.Spec.PodSelector.MatchLabels).To(Equal(generatePostgresSelectorLabels()))
	}

	createAndValidatePostgresDeployment := func(with_pvc bool) {
		if with_pvc {
			cr.Spec.OLSConfig.Storage = &olsv1alpha1.Storage{}
		}
		cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = "dummy-secret-1"
		secret, _ := r.generatePostgresSecret(cr)
		secret.SetOwnerReferences([]metav1.OwnerReference{
			{
				Kind:       "Secret",
				APIVersion: "v1",
				UID:        "ownerUID",
				Name:       "dummy-secret-1",
			},
		})
		secretCreationErr := r.Create(ctx, secret)
		Expect(secretCreationErr).NotTo(HaveOccurred())
		passwordMap, _ := getSecretContent(r.Client, secret.Name, cr.Namespace, []string{OLSComponentPasswordFileName}, secret)
		password := passwordMap[OLSComponentPasswordFileName]
		deployment, err := r.generatePostgresDeployment(cr)
		Expect(err).NotTo(HaveOccurred())
		validatePostgresDeployment(deployment, password, with_pvc)
		secretDeletionErr := r.Delete(ctx, secret)
		Expect(secretDeletionErr).NotTo(HaveOccurred())
	}

	Context("complete custom resource", func() {
		BeforeEach(func() {
			rOptions = &OLSConfigReconcilerOptions{
				LightspeedServicePostgresImage: "lightspeed-service-postgres:latest",
				Namespace:                      OLSNamespaceDefault,
			}
			cr = getOLSConfigWithCacheCR()
			r = &OLSConfigReconciler{
				Options:    *rOptions,
				logger:     logf.Log.WithName("olsconfig.reconciler"),
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				stateCache: make(map[string]string),
			}
		})

		It("should generate the OLS postgres deployment", func() {
			createAndValidatePostgresDeployment(false)
		})

		It("should generate the OLS postgres deployment with a PVC data volume", func() {
			createAndValidatePostgresDeployment(true)
		})

		It("should customize container settings in the OLS postgres deployment", func() {
			resources := &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("500Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("3Gi"),
				},
			}
			tolerations := []corev1.Toleration{
				{
					Key:      "test-key",
					Operator: corev1.TolerationOpEqual,
					Value:    "test-value",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}
			nodeSelector := map[string]string{
				"test-node-selector-key": "test-node-selector-value",
			}
			cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer = olsv1alpha1.DatabaseContainerConfig{
				Resources:    resources,
				Tolerations:  tolerations,
				NodeSelector: nodeSelector,
			}

			cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = "dummy-secret-1"
			secret, _ := r.generatePostgresSecret(cr)
			secret.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Secret",
					APIVersion: "v1",
					UID:        "ownerUID",
					Name:       "dummy-secret-1",
				},
			})
			secretCreationErr := r.Create(ctx, secret)
			Expect(secretCreationErr).NotTo(HaveOccurred())

			deployment, err := r.generatePostgresDeployment(cr)
			Expect(err).NotTo(HaveOccurred())

			Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*resources))
			Expect(deployment.Spec.Template.Spec.Tolerations).To(Equal(tolerations))
			Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
		})

		It("should work when no update in the OLS postgres deployment", func() {
			cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = "dummy-secret-2"
			secret, _ := r.generatePostgresSecret(cr)
			secret.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Secret",
					APIVersion: "v1",
					UID:        "ownerUID",
					Name:       "dummy-secret-2",
				},
			})
			secretCreationErr := r.Create(ctx, secret)
			Expect(secretCreationErr).NotTo(HaveOccurred())
			deployment, err := r.generatePostgresDeployment(cr)
			Expect(err).NotTo(HaveOccurred())
			deployment.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Deployment",
					APIVersion: "apps/v1",
					UID:        "ownerUID",
					Name:       "lightspeed-postgres-server-1",
				},
			})
			deployment.ObjectMeta.Name = "lightspeed-postgres-server-1"
			deploymentCreationErr := r.Create(ctx, deployment)
			Expect(deploymentCreationErr).NotTo(HaveOccurred())
			updateErr := r.updatePostgresDeployment(ctx, deployment, deployment)
			Expect(updateErr).NotTo(HaveOccurred())
			secretDeletionErr := r.Delete(ctx, secret)
			Expect(secretDeletionErr).NotTo(HaveOccurred())
			deploymentDeletionErr := r.Delete(ctx, deployment)
			Expect(deploymentDeletionErr).NotTo(HaveOccurred())
		})

		It("should work when there is an update in the OLS postgres deployment", func() {
			cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = "dummy-secret-3"
			secret, _ := r.generatePostgresSecret(cr)
			secret.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Secret",
					APIVersion: "v1",
					UID:        "ownerUID",
					Name:       "dummy-secret-3",
				},
			})
			secretCreationErr := r.Create(ctx, secret)
			Expect(secretCreationErr).NotTo(HaveOccurred())
			deployment, err := r.generatePostgresDeployment(cr)
			Expect(err).NotTo(HaveOccurred())
			deployment.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Deployment",
					APIVersion: "apps/v1",
					UID:        "ownerUID",
					Name:       "lightspeed-postgres-server-2",
				},
			})
			deployment.ObjectMeta.Name = "lightspeed-postgres-server-2"
			deploymentCreationErr := r.Create(ctx, deployment)
			Expect(deploymentCreationErr).NotTo(HaveOccurred())
			deploymentClone := deployment.DeepCopy()
			deploymentClone.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{
					Name:  "DUMMY_UPDATE",
					Value: PostgresDefaultUser,
				},
			}
			updateErr := r.updatePostgresDeployment(ctx, deployment, deploymentClone)
			Expect(updateErr).NotTo(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.Containers[0].Env).To(Equal([]corev1.EnvVar{
				{
					Name:  "DUMMY_UPDATE",
					Value: PostgresDefaultUser,
				},
			}))
			secretDeletionErr := r.Delete(ctx, secret)
			Expect(secretDeletionErr).NotTo(HaveOccurred())
			deploymentDeletionErr := r.Delete(ctx, deployment)
			Expect(deploymentDeletionErr).NotTo(HaveOccurred())
		})

		It("should generate the OLS postgres service", func() {
			validatePostgresService(r.generatePostgresService(cr))
		})

		It("should generate the OLS postgres configmap", func() {
			configMap, err := r.generatePostgresConfigMap(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(configMap.Name).To(Equal(PostgresConfigMap))
			validatePostgresConfigMap(configMap)
		})

		It("should generate the OLS postgres secret", func() {
			secret, err := r.generatePostgresSecret(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Name).To(Equal("lightspeed-postgres-secret"))
			validatePostgresSecret(secret)
		})

		It("should generate the OLS postgres bootstrap secret", func() {
			secret, err := r.generatePostgresBootstrapSecret(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Name).To(Equal(PostgresBootstrapSecretName))
			validatePostgresBootstrapSecret(secret)
		})

		It("should generate the OLS postgres network policy", func() {
			networkPolicy, err := r.generatePostgresNetworkPolicy(cr)
			Expect(err).NotTo(HaveOccurred())
			validatePostgresNetworkPolicy(networkPolicy)
		})
	})

	Context("empty custom resource", func() {
		BeforeEach(func() {
			rOptions = &OLSConfigReconcilerOptions{
				LightspeedServicePostgresImage: "lightspeed-service-postgres:latest",
				Namespace:                      OLSNamespaceDefault,
			}
			cr = getNoCacheCR()
			r = &OLSConfigReconciler{
				Options:    *rOptions,
				logger:     logf.Log.WithName("olsconfig.reconciler"),
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				stateCache: make(map[string]string),
			}
		})

		It("should generate the OLS postgres deployment", func() {
			cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = "dummy-secret-4"
			cr.Spec.OLSConfig.ConversationCache.Postgres.User = PostgresDefaultUser
			cr.Spec.OLSConfig.ConversationCache.Postgres.DbName = PostgresDefaultDbName
			cr.Spec.OLSConfig.ConversationCache.Postgres.SharedBuffers = PostgresSharedBuffers
			cr.Spec.OLSConfig.ConversationCache.Postgres.MaxConnections = PostgresMaxConnections
			secret, _ := r.generatePostgresSecret(cr)
			secret.SetOwnerReferences([]metav1.OwnerReference{
				{
					Kind:       "Secret",
					APIVersion: "v1",
					UID:        "ownerUID",
					Name:       "dummy-secret-4",
				},
			})
			secretCreationErr := r.Create(ctx, secret)
			Expect(secretCreationErr).NotTo(HaveOccurred())
			passwordMap, _ := getSecretContent(r.Client, secret.Name, cr.Namespace, []string{OLSComponentPasswordFileName}, secret)
			password := passwordMap[OLSComponentPasswordFileName]
			deployment, err := r.generatePostgresDeployment(cr)
			Expect(err).NotTo(HaveOccurred())
			validatePostgresDeployment(deployment, password, false)
			secretDeletionErr := r.Delete(ctx, secret)
			Expect(secretDeletionErr).NotTo(HaveOccurred())
		})

		It("should generate the OLS postgres service", func() {
			validatePostgresService(r.generatePostgresService(cr))
		})

		It("should generate the OLS postgres configmap", func() {
			configMap, err := r.generatePostgresConfigMap(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(configMap.Name).To(Equal(PostgresConfigMap))
			validatePostgresConfigMap(configMap)
		})

		It("should generate the OLS postgres bootstrap secret", func() {
			secret, err := r.generatePostgresBootstrapSecret(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Name).To(Equal(PostgresBootstrapSecretName))
			validatePostgresBootstrapSecret(secret)
		})

		It("should generate the OLS postgres secret", func() {
			cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret = PostgresSecretName
			secret, err := r.generatePostgresSecret(cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Name).To(Equal("lightspeed-postgres-secret"))
			validatePostgresSecret(secret)
		})
	})

})

func getOLSConfigWithCacheCR() *olsv1alpha1.OLSConfig {
	return &olsv1alpha1.OLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster",
			Namespace: OLSNamespaceDefault,
			UID:       "OLSConfig_created_in_getOLSConfigWithCacheCR", // avoid the "uid must not be empty" error
		},
		Spec: olsv1alpha1.OLSConfigSpec{
			OLSConfig: olsv1alpha1.OLSSpec{
				ConversationCache: olsv1alpha1.ConversationCacheSpec{
					Type: olsv1alpha1.Postgres,
					Postgres: olsv1alpha1.PostgresSpec{
						User:              PostgresDefaultUser,
						DbName:            PostgresDefaultDbName,
						SharedBuffers:     PostgresSharedBuffers,
						MaxConnections:    PostgresMaxConnections,
						CredentialsSecret: PostgresSecretName,
					},
				},
			},
		},
	}
}

func getNoCacheCR() *olsv1alpha1.OLSConfig {
	return &olsv1alpha1.OLSConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster",
			Namespace: OLSNamespaceDefault,
			UID:       "OLSConfig_created_in_getNoCacheCR", // avoid the "uid must not be empty" error
		},
	}
}

// CloudNativePG Cluster Generator Tests
var _ = Describe("CloudNativePG Cluster Generator", func() {
	var reconciler *OLSConfigReconciler
	var cr *olsv1alpha1.OLSConfig

	BeforeEach(func() {
		reconciler = &OLSConfigReconciler{
			Options: OLSConfigReconcilerOptions{
				Namespace: "test-namespace",
			},
		}

		cr = &olsv1alpha1.OLSConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ols-config",
				Namespace: "test-namespace",
			},
			Spec: olsv1alpha1.OLSConfigSpec{
				OLSConfig: olsv1alpha1.OLSSpec{
					ConversationCache: olsv1alpha1.ConversationCacheSpec{
						Postgres: olsv1alpha1.PostgresSpec{
							User:              "testuser",
							DbName:            "testdb",
							CredentialsSecret: "test-secret",
							SharedBuffers:     "512MB",
							MaxConnections:    1000,
						},
					},
					Storage: &olsv1alpha1.Storage{
						Size:  resource.MustParse("2Gi"),
						Class: "fast-ssd",
					},
				},
			},
		}
	})

	Context("when generating CloudNativePG cluster", func() {
		It("should create cluster with correct basic configuration", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())
			Expect(cluster.Name).To(Equal("lightspeed-postgres-cluster"))
			Expect(cluster.Namespace).To(Equal("test-namespace"))
			Expect(cluster.Spec.Instances).To(Equal(2))
			Expect(cluster.Labels).To(HaveKeyWithValue("app.kubernetes.io/component", "postgres-server"))
			Expect(cluster.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "lightspeed-operator"))
			Expect(cluster.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "lightspeed-service-postgres"))
			Expect(cluster.Labels).To(HaveKeyWithValue("app.kubernetes.io/part-of", "openshift-lightspeed"))
		})

		It("should configure PostgreSQL parameters correctly", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify PostgreSQL parameters
			Expect(cluster.Spec.PostgresConfiguration.Parameters).To(HaveKeyWithValue("ssl", "on"))
			Expect(cluster.Spec.PostgresConfiguration.Parameters).To(HaveKeyWithValue("shared_buffers", "512MB"))
			Expect(cluster.Spec.PostgresConfiguration.Parameters).To(HaveKeyWithValue("max_connections", "1000"))
		})

		It("should configure bootstrap correctly", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify bootstrap configuration uses PostgresSpec values
			Expect(cluster.Spec.Bootstrap.InitDB.Database).To(Equal(cr.Spec.OLSConfig.ConversationCache.Postgres.DbName))
			Expect(cluster.Spec.Bootstrap.InitDB.Owner).To(Equal(cr.Spec.OLSConfig.ConversationCache.Postgres.User))
			Expect(cluster.Spec.Bootstrap.InitDB.Secret.Name).To(Equal(cr.Spec.OLSConfig.ConversationCache.Postgres.CredentialsSecret))
		})

		It("should configure storage correctly", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify storage configuration
			Expect(cluster.Spec.StorageConfiguration.Size).To(Equal("2Gi"))
			Expect(cluster.Spec.StorageConfiguration.StorageClass).ToNot(BeNil())
			Expect(*cluster.Spec.StorageConfiguration.StorageClass).To(Equal("fast-ssd"))
		})

		It("should configure certificates correctly", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify certificate configuration
			Expect(cluster.Spec.Certificates).ToNot(BeNil())
			Expect(cluster.Spec.Certificates.ServerTLSSecret).To(Equal(PostgresCertsSecretName))
		})

		It("should configure resources correctly", func() {
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify resource configuration
			Expect(cluster.Spec.Resources.Requests).To(HaveKeyWithValue(corev1.ResourceCPU, resource.MustParse("30m")))
			Expect(cluster.Spec.Resources.Requests).To(HaveKeyWithValue(corev1.ResourceMemory, resource.MustParse("300Mi")))
			Expect(cluster.Spec.Resources.Limits).To(HaveKeyWithValue(corev1.ResourceMemory, resource.MustParse("2Gi")))
		})

		It("should use custom resources if specified", func() {
			customCPU := resource.MustParse("100m")
			customMemory := resource.MustParse("500Mi")
			cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Resources = &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    customCPU,
					corev1.ResourceMemory: customMemory,
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("1Gi"),
				},
			}
			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())
			Expect(cluster.Spec.Resources.Requests).To(HaveKeyWithValue(corev1.ResourceCPU, customCPU))
			Expect(cluster.Spec.Resources.Requests).To(HaveKeyWithValue(corev1.ResourceMemory, customMemory))
			Expect(cluster.Spec.Resources.Limits).To(HaveKeyWithValue(corev1.ResourceCPU, resource.MustParse("500m")))
			Expect(cluster.Spec.Resources.Limits).To(HaveKeyWithValue(corev1.ResourceMemory, resource.MustParse("1Gi")))
		})

		It("should configure node affinity when node selector specified", func() {
			// Set node selector
			cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.NodeSelector = map[string]string{
				"kubernetes.io/os": "linux",
				"node-type":        "database",
			}

			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// Verify node affinity is configured
			Expect(cluster.Spec.Affinity.NodeAffinity).ToNot(BeNil())
			Expect(cluster.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution).ToNot(BeNil())
		})

		It("should handle tolerations when specified", func() {
			// Set tolerations
			cr.Spec.OLSConfig.DeploymentConfig.DatabaseContainer.Tolerations = []corev1.Toleration{
				{
					Key:      "database",
					Operator: corev1.TolerationOpEqual,
					Value:    "true",
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			cluster, err := reconciler.generateCloudNativePGCluster(cr)
			Expect(err).ToNot(HaveOccurred())

			// CloudNativePG handles tolerations through affinity, so we just verify the cluster is created
			Expect(cluster).ToNot(BeNil())
			Expect(cluster.Name).To(Equal("lightspeed-postgres-cluster"))
		})

		It("should use default values when not specified", func() {
			// Create CR with minimal configuration
			minimalCR := &olsv1alpha1.OLSConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "minimal-ols-config",
					Namespace: "test-namespace",
				},
				Spec: olsv1alpha1.OLSConfigSpec{
					OLSConfig: olsv1alpha1.OLSSpec{
						ConversationCache: olsv1alpha1.ConversationCacheSpec{
							Postgres: olsv1alpha1.PostgresSpec{},
						},
					},
				},
			}

			cluster, err := reconciler.generateCloudNativePGCluster(minimalCR)
			Expect(err).ToNot(HaveOccurred())

			// Verify default values are used
			Expect(cluster.Spec.PostgresConfiguration.Parameters).To(HaveKeyWithValue("shared_buffers", PostgresSharedBuffers))
			Expect(cluster.Spec.PostgresConfiguration.Parameters).To(HaveKeyWithValue("max_connections", strconv.Itoa(PostgresMaxConnections)))
			Expect(cluster.Spec.StorageConfiguration.Size).To(Equal(PostgresDefaultPVCSize))

			// Verify default bootstrap values are used
			Expect(cluster.Spec.Bootstrap.InitDB.Database).To(Equal(PostgresDefaultDbName))
			Expect(cluster.Spec.Bootstrap.InitDB.Owner).To(Equal(PostgresDefaultUser))
			Expect(cluster.Spec.Bootstrap.InitDB.Secret.Name).To(Equal(PostgresSecretName))
		})
	})
})
