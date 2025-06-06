/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/gomega"
	cnstypes "github.com/vmware/govmomi/cns/types"

	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/csi/service/logger"
)

const (
	AdminUser                                  = "Administrator@vsphere.local"
	ApiServerIPs                               = "API_SERVER_IPS"
	AttacherContainerName                      = "csi-attacher"
	NginxImage                                 = "registry.k8s.io/nginx-slim:0.26"
	NginxImage4upg                             = "registry.k8s.io/nginx-slim:0.27"
	RetainClaimPolicy                          = "Retain"
	CloudInitLabel                             = "CloudInit"
	ConfigSecret                               = "vsphere-config-secret"
	ContollerClusterKubeConfig                 = "CONTROLLER_CLUSTER_KUBECONFIG"
	ControlPlaneLabel                          = "node-role.kubernetes.io/control-plane"
	CrdCNSNodeVMAttachment                     = "cnsnodevmattachments"
	CrdCNSVolumeMetadatas                      = "cnsvolumemetadatas"
	CrdCNSFileAccessConfig                     = "cnsfileaccessconfigs"
	CrdtriggercsifullsyncsName                 = "csifullsync"
	CrdGroup                                   = "cns.vmware.com"
	CrdVersion                                 = "v1alpha1"
	CrdVirtualMachineImages                    = "virtualmachineimages"
	CrdVirtualMachines                         = "virtualmachines"
	CrdVirtualMachineService                   = "virtualmachineservice"
	csiSystemNamespace                         = "vmware-system-csi"
	CsiFssCM                                   = "internal-feature-states.csi.vsphere.vmware.com"
	CsiVolAttrVolType                          = "vSphere CNS Block Volume"
	CsiDriverContainerName                     = "vsphere-csi-controller"
	Datacenter                                 = "DATACENTER"
	DefaultFullSyncIntervalInMin               = "30"
	DefaultProvisionerTimeInSec                = "300"
	DefaultFullSyncWaitTime                    = 1800
	DefaultPandoraSyncWaitTime                 = 90
	DefaultK8sNodesUpWaitTime                  = 25
	DestinationDatastoreURL                    = "DESTINATION_VSPHERE_DATASTORE_URL"
	DisklibUnlinkErr                           = "DiskLib_Unlink"
	DiskSize1GB                                = "1Gi"
	DiskSize                                   = "2Gi"
	DiskSizeLarge                              = "100Gi"
	DiskSizeInMb                               = int64(2048)
	DiskSizeInMinMb                            = int64(200)
	E2eTestPassword                            = "E2E-test-password!23"
	E2evSphereCSIDriverName                    = "csi.vsphere.vmware.com"
	EnsureAccessibilityMModeType               = "ensureObjectAccessibility"
	EnvClusterFlavor                           = "CLUSTER_FLAVOR"
	EnvDiskSizeLarge                           = "LARGE_DISK_SIZE"
	EnvCSINamespace                            = "CSI_NAMESPACE"
	EnvContentLibraryUrl                       = "CONTENT_LIB_URL"
	EnvContentLibraryUrlSslThumbprint          = "CONTENT_LIB_THUMBPRINT"
	EnvEsxHostIP                               = "ESX_TEST_HOST_IP"
	EnvFileServiceDisabledSharedDatastoreURL   = "FILE_SERVICE_DISABLED_SHARED_VSPHERE_DATASTORE_URL"
	EnvFullSyncWaitTime                        = "FULL_SYNC_WAIT_TIME"
	EnvGatewayVmIp                             = "GATEWAY_VM_IP"
	EnvGatewayVmUser                           = "GATEWAY_VM_USER"
	EnvGatewayVmPasswd                         = "GATEWAY_VM_PASSWD"
	EnvHciMountRemoteDs                        = "USE_HCI_MESH_DS"
	EnvInaccessibleZoneDatastoreURL            = "INACCESSIBLE_ZONE_VSPHERE_DATASTORE_URL"
	EnvNonSharedStorageClassDatastoreURL       = "NONSHARED_VSPHERE_DATASTORE_URL"
	EnvPandoraSyncWaitTime                     = "PANDORA_SYNC_WAIT_TIME"
	EnvK8sNodesUpWaitTime                      = "K8S_NODES_UP_WAIT_TIME"
	EnvRegionZoneWithNoSharedDS                = "TOPOLOGY_WITH_NO_SHARED_DATASTORE"
	EnvRegionZoneWithSharedDS                  = "TOPOLOGY_WITH_SHARED_DATASTORE"
	EnvRemoteHCIDsUrl                          = "REMOTE_HCI_DS_URL"
	EnvSharedDatastoreURL                      = "SHARED_VSPHERE_DATASTORE_URL"
	EnvSharedVVOLDatastoreURL                  = "SHARED_VVOL_DATASTORE_URL"
	EnvSharedNFSDatastoreURL                   = "SHARED_NFS_DATASTORE_URL"
	EnvSharedVMFSDatastoreURL                  = "SHARED_VMFS_DATASTORE_URL"
	EnvSharedVMFSDatastore2URL                 = "SHARED_VMFS_DATASTORE2_URL"
	EnvVMClass                                 = "VM_CLASS"
	EnvVsanDirectSetup                         = "USE_VSAN_DIRECT_DATASTORE_IN_WCP"
	EnvVsanDDatastoreURL                       = "SHARED_VSAND_DATASTORE_URL"
	EnvVsanDDatastore2URL                      = "SHARED_VSAND_DATASTORE2_URL"
	EnvStoragePolicyNameForNonSharedDatastores = "STORAGE_POLICY_FOR_NONSHARED_DATASTORES"
	EnvStoragePolicyNameForSharedDatastores    = "STORAGE_POLICY_FOR_SHARED_DATASTORES"
	EnvStoragePolicyNameForHCIRemoteDatastores = "STORAGE_POLICY_FOR_HCI_REMOTE_DS"
	EnvStoragePolicyNameForVsanVmfsDatastores  = "STORAGE_POLICY_FOR_VSAN_VMFS_DATASTORES"
	EnvStoragePolicyNameForSharedDatastores2   = "STORAGE_POLICY_FOR_SHARED_DATASTORES_2"
	EnvStoragePolicyNameForVmfsDatastores      = "STORAGE_POLICY_FOR_VMFS_DATASTORES"
	EnvStoragePolicyNameForNfsDatastores       = "STORAGE_POLICY_FOR_NFS_DATASTORES"
	EnvStoragePolicyNameForVvolDatastores      = "STORAGE_POLICY_FOR_VVOL_DATASTORES"
	EnvStoragePolicyNameFromInaccessibleZone   = "STORAGE_POLICY_FROM_INACCESSIBLE_ZONE"
	EnvStoragePolicyNameWithThickProvision     = "STORAGE_POLICY_WITH_THICK_PROVISIONING"
	EnvStoragePolicyNameWithEncryption         = "STORAGE_POLICY_WITH_ENCRYPTION"
	EnvKeyProvider                             = "KEY_PROVIDER"
	EnvSupervisorClusterNamespace              = "SVC_NAMESPACE"
	EnvSupervisorClusterNamespaceToDelete      = "SVC_NAMESPACE_TO_DELETE"
	EnvTopologyWithOnlyOneNode                 = "TOPOLOGY_WITH_ONLY_ONE_NODE"
	EnvTopologyWithInvalidTagInvalidCat        = "TOPOLOGY_WITH_INVALID_TAG_INVALID_CAT"
	EnvTopologyWithInvalidTagValidCat          = "TOPOLOGY_WITH_INVALID_TAG_VALID_CAT"
	EnvNumberOfGoRoutines                      = "NUMBER_OF_GO_ROUTINES"
	EnvWorkerPerRoutine                        = "WORKER_PER_ROUTINE"
	EnvVmdkDiskURL                             = "DISK_URL_PATH"
	EnvVmsvcVmImageName                        = "VMSVC_IMAGE_NAME"
	EnvVolumeOperationsScale                   = "VOLUME_OPS_SCALE"
	EnvComputeClusterName                      = "COMPUTE_CLUSTER_NAME"
	EnvTKGImage                                = "TKG_IMAGE_NAME"
	EnvVmknic4Vsan                             = "VMKNIC_FOR_VSAN"
	ExecCommand                                = "/bin/df -T /mnt/volume1 | " +
		"/bin/awk 'FNR == 2 {print $2}' > /mnt/volume1/fstype && while true ; do sleep 2 ; done"
	ExecRWXCommandPod = "echo 'Hello message from Pod' > /mnt/volume1/Pod.html  && " +
		"chmod o+rX /mnt /mnt/volume1/Pod.html && while true ; do sleep 2 ; done"
	ExecRWXCommandPod1 = "echo 'Hello message from Pod1' > /mnt/volume1/Pod1.html  && " +
		"chmod o+rX /mnt /mnt/volume1/Pod1.html && while true ; do sleep 2 ; done"
	ExecRWXCommandPod2 = "echo 'Hello message from Pod2' > /mnt/volume1/Pod2.html  && " +
		"chmod o+rX /mnt /mnt/volume1/Pod2.html && while true ; do sleep 2 ; done"
	Ext3FSType                                = "ext3"
	Ext4FSType                                = "ext4"
	XfsFSType                                 = "xfs"
	EvacMModeType                             = "evacuateAllData"
	FcdName                                   = "BasicStaticFCD"
	FileSizeInMb                              = int64(2048)
	FilePathPod                               = "/mnt/volume1/Pod.html"
	FilePathPod1                              = "/mnt/volume1/Pod1.html"
	FilePathPod2                              = "/mnt/volume1/Pod2.html"
	FilePathFsType                            = "/mnt/volume1/fstype"
	FullSyncFss                               = "trigger-csi-fullsync"
	GcNodeUser                                = "vmware-system-user"
	GcKubeConfigPath                          = "GC_KUBE_CONFIG"
	GcSshKey                                  = "TEST-CLUSTER-SSH-KEY"
	HealthGreen                               = "green"
	HealthRed                                 = "red"
	HealthStatusAccessible                    = "accessible"
	HealthStatusInAccessible                  = "inaccessible"
	HealthStatusWaitTime                      = 3 * time.Minute
	HostdServiceName                          = "hostd"
	InvalidFSType                             = "ext10"
	K8sPodTerminationTimeOut                  = 7 * time.Minute
	K8sPodTerminationTimeOutLong              = 10 * time.Minute
	KcmManifest                               = "/etc/kubernetes/manifests/kube-controller-manager.yaml"
	KubeAPIPath                               = "/etc/kubernetes/manifests/"
	KubeAPIfile                               = "kube-apiserver.yaml"
	KubeAPIRecoveryTime                       = 1 * time.Minute
	KubeSystemNamespace                       = "kube-system"
	KubeletConfigYaml                         = "/var/lib/kubelet/config.yaml"
	Nfs4FSType                                = "nfs4"
	MmStateChangeTimeout                      = 300 // int
	ObjOrItemNotFoundErr                      = "The object or item referred to could not be found"
	PassorwdFilePath                          = "/etc/vmware/wcp/.storageUser"
	PodContainerCreatingState                 = "ContainerCreating"
	Poll                                      = 2 * time.Second
	PollTimeout                               = 10 * time.Minute
	PollTimeoutShort                          = 1 * time.Minute
	PollTimeoutSixMin                         = 6 * time.Minute
	HealthStatusPollTimeout                   = 20 * time.Minute
	HealthStatusPollInterval                  = 30 * time.Second
	PsodTime                                  = "120"
	PvcHealthAnnotation                       = "volumehealth.storage.kubernetes.io/health"
	PvcHealthTimestampAnnotation              = "volumehealth.storage.kubernetes.io/health-timestamp"
	ProvisionerContainerName                  = "csi-provisioner"
	QuotaName                                 = "cns-test-quota"
	RegionKey                                 = "topology.csi.vmware.com/k8s-region"
	ResizePollInterval                        = 2 * time.Second
	RestartOperation                          = "restart"
	RqLimit                                   = "200Gi"
	RqLimitScaleTest                          = "900Gi"
	RootUser                                  = "root"
	DefaultrqLimit                            = "20Gi"
	RqStorageType                             = ".storageclass.storage.k8s.io/requests.storage"
	ResizerContainerName                      = "csi-resizer"
	ScParamDatastoreURL                       = "DatastoreURL"
	ScParamFsType                             = "csi.storage.k8s.io/fstype"
	ScParamStoragePolicyID                    = "storagePolicyID"
	ScParamStoragePolicyName                  = "StoragePolicyName"
	ShortProvisionerTimeout                   = "10"
	Snapshotapigroup                          = "snapshot.storage.k8s.io"
	SleepTimeOut                              = 30
	OneMinuteWaitTimeInSeconds                = 60
	SpsServiceName                            = "sps"
	SnapshotterContainerName                  = "csi-snapshotter"
	SshdPort                                  = "22"
	SshSecretName                             = "SSH_SECRET_NAME"
	SvcRunningMessage                         = "Running"
	SvcMasterIP                               = "SVC_MASTER_IP"
	SvcMasterPassword                         = "SVC_MASTER_PASSWORD"
	StartOperation                            = "start"
	SvcStoppedMessage                         = "Stopped"
	StopOperation                             = "stop"
	StatusOperation                           = "status"
	EnvZonalStoragePolicyName                 = "ZONAL_STORAGECLASS"
	EnvZonalWffcStoragePolicyName             = "ZONAL_WFFC_STORAGECLASS"
	SupervisorClusterOperationsTimeout        = 3 * time.Minute
	SvClusterDistribution                     = "SupervisorCluster"
	SvOperationTimeout                        = 240 * time.Second
	SvStorageClassName                        = "SVStorageClass"
	SyncerContainerName                       = "vsphere-syncer"
	TotalResizeWaitPeriod                     = 10 * time.Minute
	TkgClusterDistribution                    = "TKGService"
	VanillaClusterDistribution                = "CSI-Vanilla"
	VanillaClusterDistributionWithSpecialChar = "CSI-\tVanilla-#Test"
	VcClusterAPI                              = "/api/vcenter/namespace-management/clusters"
	VcRestSessionIdHeaderName                 = "vmware-api-session-Id"
	VpxdServiceName                           = "vpxd"
	VpxdReducedTaskTimeoutSecsInt             = 90
	VSphereCSIControllerPodNamePrefix         = "vsphere-csi-controller"
	VmUUIDLabel                               = "vmware-system-vm-uuid"
	VsanLabel                                 = "vsan"
	VsanDefaultStorageClassInSVC              = "vsan-default-storage-policy"
	VsanDefaultStoragePolicyName              = "vSAN Default Storage Policy"
	VsanHealthServiceWaitTime                 = 15
	VsanhealthServiceName                     = "vsan-health"
	VsphereCloudProviderConfiguration         = "vsphere-cloud-provider.conf"
	VsphereControllerManager                  = "vmware-system-tkg-controller-manager"
	VSphereCSIConf                            = "csi-vsphere.conf"
	VsphereTKGSystemNamespace                 = "svc-tkg-domain-c10"
	WaitTimeForCNSNodeVMAttachmentReconciler  = 30 * time.Second
	WcpServiceName                            = "wcp"
	VmcWcpHost                                = "10.2.224.24" //This is the LB IP of VMC WCP and its constant
	DevopsTKG                                 = "test-cluster-e2e-script"
	CloudadminTKG                             = "test-cluster-e2e-script-1"
	VmOperatorAPI                             = "/apis/vmoperator.vmware.com/v1alpha1/"
	DevopsUser                                = "testuser"
	ZoneKey                                   = "topology.csi.vmware.com/k8s-zone"
	TkgAPI                                    = "/apis/run.tanzu.vmware.com/v1alpha3/namespaces" +
		"/test-gc-e2e-demo-ns/tanzukubernetesclusters/"
	Topologykey                                = "topology.csi.vmware.com"
	EnvTopologyMap                             = "TOPOLOGY_MAP"
	TopologyHaMap                              = "TOPOLOGY_HA_MAP"
	TopologyFeature                            = "TOPOLOGY_FEATURE"
	TopologyTkgHaName                          = "tkgs_ha"
	TkgHATopologyKey                           = "topology.kubernetes.io"
	TkgHAccessibleAnnotationKey                = "csi.vsphere.volume-accessible-topology"
	TkgHARequestedAnnotationKey                = "csi.vsphere.volume-requested-topology"
	DatstoreSharedBetweenClusters              = "DATASTORE_SHARED_BETWEEN_TWO_CLUSTERS"
	DatastoreUrlSpecificToCluster              = "DATASTORE_URL_SPECIFIC_TO_CLUSTER"
	StoragePolicyForDatastoreSpecificToCluster = "STORAGE_POLICY_FOR_DATASTORE_SPECIFIC_TO_CLUSTER"
	TopologyCluster                            = "TOPOLOGY_CLUSTERS"
	TopologyLength                             = 5
	TkgshaTopologyLevels                       = 1
	VmClassBestEffortSmall                     = "best-effort-small"
	VmcPrdEndpoint                             = "https://vmc.vmware.com/vmc/api/orgs/"
	VsphereClusterIdConfigMapName              = "vsphere-csi-cluster-id"
	AuthAPI                                    = "https://console.cloud.vmware.com/csp/gateway/am/api/auth" +
		"/api-tokens/authorize"
	StoragePolicyQuota                       = "-storagepolicyquota"
	PodVMOnStretchedSupervisor               = "stretched-svc"
	StretchedSVCTopologyLevels               = 1
	EnvZonalStoragePolicyName2               = "ZONAL2_STORAGECLASS"
	VolExtensionName                         = "volume.cns.vsphere.vmware.com"
	SnapshotExtensionName                    = "snapshot.cns.vsphere.vmware.com"
	VmServiceExtensionName                   = "vmservice.cns.vsphere.vmware.com"
	PvcUsage                                 = "-pvc-usage"
	SnapshotUsage                            = "-snapshot-usage"
	VmUsage                                  = "-vm-usage"
	DiskSize1Gi                              = int64(1024)
	StorageQuotaWebhookPrefix                = "storage-quota-webhook"
	EnvStoragePolicyNameForVsanNfsDatastores = "STORAGE_POLICY_FOR_VSAN_NFS_DATASTORES"
	DevopsKubeConf                           = "DEV_OPS_USER_KUBECONFIG"
	QuotaSupportedVCVersion                  = "9.0.0"
)

/*
// test suite labels

flaky -> label include the testcases which fails intermittently
disruptive -> label include the testcases which are disruptive in nature  ex: hosts down, cluster down, datastore down
vanilla -> label include the testcases for block, file, configSecret, topology etc.
stable -> label include the testcases which do not fail
longRunning -> label include the testcases which takes longer time for completion
p0 -> label include the testcases which are P0
p1 -> label include the testcases which are P1, vcreboot, negative
p2 -> label include the testcases which are P2
semiAutomated -> label include the testcases which are semi-automated
newTests -> label include the testcases which are newly automated
core -> label include the testcases specific to block or file
level2 -> label include the level-2 topology testcases or pipeline specific
level5 -> label include the level-5 topology testcases
customPort -> label include the testcases running on vCenter custom port <VC:444>
deprecated ->label include the testcases which are no longer in execution
negative -> Negative tests, ex: service/pod down(sps, vsan-health, vpxd, hostd, csi pods)
vc70 -> Tests for vc70 features
vc80 -> Tests for vc80 features
vc80 -> Tests for vc90 features
vmServiceVm -> vmService VM related testcases
wldi -> Work-Load Domain Isolation testcases
*/
const (
	Flaky                 = "flaky"
	Disruptive            = "disruptive"
	Wcp                   = "wcp"
	Tkg                   = "tkg"
	Vanilla               = "vanilla"
	Preferential          = "preferential"
	VsphereConfigSecret   = "vsphereConfigSecret"
	Snapshot              = "snapshot"
	Stable                = "stable"
	NewTest               = "newTest"
	MultiVc               = "multiVc"
	Block                 = "block"
	File                  = "file"
	Core                  = "core"
	Hci                   = "hci"
	P0                    = "p0"
	P1                    = "p1"
	P2                    = "p2"
	VsanStretch           = "vsanStretch"
	LongRunning           = "longRunning"
	Deprecated            = "deprecated"
	Vmc                   = "vmc"
	TkgsHA                = "tkgsHA"
	ThickThin             = "thickThin"
	CustomPort            = "customPort"
	Windows               = "windows"
	SemiAutomated         = "semiAutomated"
	Level2                = "level2"
	Level5                = "level5"
	Negative              = "negative"
	ListVolume            = "listVolume"
	MultiSvc              = "multiSvc"
	PrimaryCentric        = "primaryCentric"
	ControlPlaneOnPrimary = "controlPlaneOnPrimary"
	Distributed           = "distributed"
	Vmsvc                 = "vmsvc"
	Vc90                  = "vc90"
	Vc80                  = "vc80"
	Vc70                  = "vc70"
	Wldi                  = "wldi"
	VmServiceVm           = "vmServiceVm"
	VcptocsiTest          = "vcptocsiTest"
	StretchedSvc          = "stretchedSvc"
	Devops                = "devops"
)

// The following variables are required to know cluster type to run common e2e
// tests. These variables will be set once during test suites initialization.
var (
	VanillaCluster       bool
	SupervisorCluster    bool
	GuestCluster         bool
	RwxAccessMode        bool
	WcpVsanDirectCluster bool
	Vcptocsi             bool
	WindowsEnv           bool
	MultipleSvc          bool
	Multivc              bool
	StretchedSVC         bool
)

// For busybox pod image
var (
	BusyBoxImageOnGcr = "busybox"
)

// For VCP to CSI migration tests.
var (
	EnvSharedDatastoreName          = "SHARED_VSPHERE_DATASTORE_NAME"
	VcpProvisionerName              = "kubernetes.io/vsphere-volume"
	VcpScParamDatastoreName         = "datastore"
	VcpScParamPolicyName            = "storagePolicyName"
	VcpScParamFstype                = "fstype"
	MigratedToAnnotation            = "pv.kubernetes.io/migrated-to"
	MigratedPluginAnnotation        = "storage.alpha.kubernetes.io/migrated-plugins"
	PvcAnnotationStorageProvisioner = "volume.beta.kubernetes.io/storage-provisioner"
	PvAnnotationProvisionedBy       = "pv.kubernetes.io/provisioned-by"
	nodeMapper                      = &NodeMapper{}
)

// For vsan stretched cluster tests
var (
	EnvTestbedInfoJsonPath = "TESTBEDINFO_JSON"
)

// Config secret testuser credentials
var (
	ConfigSecretTestUser1Password = "VMware!23"
	ConfigSecretTestUser2Password = "VMware!234"
	ConfigSecretTestUser1         = "testuser1"
	ConfigSecretTestUser2         = "testuser2"
)

// Nimbus generated passwords
var (
	NimbusK8sVmPwd = "NIMBUS_K8S_VM_PWD"
	NimbusEsxPwd   = "ESX_PWD"
	NimbusVcPwd    = "VC_PWD"
	VcUIPwd        = "VC_ADMIN_PWD"
)

// volume allocation types for cns volumes
var (
	ThinAllocType = "Conserve space when possible"
	EztAllocType  = "Fully initialized"
	LztAllocType  = "Reserve space"
)

// For Preferential datatsore
var (
	PreferredDatastoreRefreshTimeInterval = 1
	PreferredDatastoreTimeOutInterval     = 1 * time.Minute
	PreferredDSCat                        = "cns.vmware.topology-preferred-datastores"
	PreferredTagDesc                      = "preferred datastore tag"
	NfsStoragePolicyName                  = "NFS_STORAGE_POLICY_NAME"
	NfstoragePolicyDatastoreUrl           = "NFS_STORAGE_POLICY_DATASTORE_URL"
	WorkerClusterMap                      = "WORKER_CLUSTER_MAP"
	DatastoreClusterMap                   = "DATASTORE_CLUSTER_MAP"
)

// For multivc
var (
	EnvSharedDatastoreURLVC1          = "SHARED_VSPHERE_DATASTORE_URL_VC1"
	EnvSharedDatastoreURLVC2          = "SHARED_VSPHERE_DATASTORE_URL_VC2"
	EnvStoragePolicyNameToDeleteLater = "STORAGE_POLICY_TO_DELETE_LATER"
	EnvMultiVCSetupType               = "MULTI_VC_SETUP_TYPE"
	EnvStoragePolicyNameVC1           = "STORAGE_POLICY_VC1"
	EnvStoragePolicyNameInVC1VC2      = "STORAGE_POLICY_NAME_COMMON_IN_VC1_VC2"
	EnvPreferredDatastoreUrlVC1       = "PREFERRED_DATASTORE_URL_VC1"
	EnvPreferredDatastoreUrlVC2       = "PREFERRED_DATASTORE_URL_VC2"
	EnvTestbedInfoJsonPathVC1         = "TESTBEDINFO_JSON_VC1"
	EnvTestbedInfoJsonPathVC2         = "TESTBEDINFO_JSON_VC2"
	EnvTestbedInfoJsonPathVC3         = "TESTBEDINFO_JSON_VC3"
)

// VolumeSnapshotClass env variables for tkg-snapshot
var (
	EnvVolSnapClassDel = "VOLUME_SNAPSHOT_CLASS_DELETE"
	DeletionPolicy     = "Delete"
)

// windows env variables
var (
	EnvWindowsUser    = "WINDOWS_USER"
	EnvWindowsPwd     = "WINDOWS_PWD"
	InvalidNtfsFSType = "NtFs1"
	NtfsFSType        = "NTFS"
	WindowsImageOnMcr = "servercore"
	WindowsExecCmd    = "while (1) " +
		" { Add-Content -Encoding Ascii /mnt/volume1/fstype.txt $([System.IO.DriveInfo]::getdrives() " +
		"| Where-Object {$_.DriveType -match 'Fixed'} | Select-Object -Property DriveFormat); sleep 1 }"
	WindowsExecRWXCommandPod = "while (1) " +
		" { Add-Content /mnt/volume1/Pod.html 'Hello message from Pod'; sleep 1 }"
	WindowsExecRWXCommandPod1 = "while (1) " +
		" { Add-Content /mnt/volume1/Pod1.html 'Hello message from Pod1'; sleep 1 }"
)

// multiSvc env variables
var (
	VcSessionWaitTime                   = 5 * time.Minute
	EnvStoragePolicyNameForSharedDsSvc1 = "STORAGE_POLICY_FOR_SHARED_DATASTORES_SVC1"
	EnvStoragePolicyNameForSharedDsSvc2 = "STORAGE_POLICY_FOR_SHARED_DATASTORES_SVC2"
	EnvSupervisorClusterNamespace1      = "SVC_NAMESPACE1"
	EnvNfsDatastoreName                 = "NFS_DATASTORE_NAME"
	EnvNfsDatastoreIP                   = "NFS_DATASTORE_IP"
	PwdRotationTimeout                  = 10 * time.Minute
	RoleCnsDatastore                    = "CNS-SUPERVISOR-DATASTORE"
	RoleCnsSearchAndSpbm                = "CNS-SUPERVISOR-SEARCH-AND-SPBM"
	RoleCnsHostConfigStorageAndCnsVm    = "CNS-SUPERVISOR-HOST-CONFIG-STORAGE-AND-CNS-VM"
)

// For rwx
var (
	EnvVsanDsStoragePolicyCluster1 = "VSAN_DATASTORE_CLUSTER1_STORAGE_POLICY"
	EnvVsanDsStoragePolicyCluster3 = "VSAN_DATASTORE_CLUSTER3_STORAGE_POLICY"
	EnvNonVsanDsUrl                = "NON_VSAN_DATASTOREURL"
	EnvVsanDsUrlCluster3           = "VSAN_DATASTOREURL_CLUSTER3"
	EnvRemoteDatastoreUrl          = "REMOTE_DATASTORE_URL"
	EnvTopologySetupType           = "TOPOLOGY_SETUP_TYPE"
)

// For management workload domain isolation
var (
	EnvZonal2StoragePolicyName            = "ZONAL2_STORAGE_POLICY_IMM"
	EnvZonal2StoragePolicyNameLateBidning = "ZONAL2_STORAGE_POLICY_WFFC"
	EnvZonal1StoragePolicyName            = "ZONAL1_STORAGE_POLICY_IMM"
	EnvZonal3StoragePolicyName            = "ZONAL3_STORAGE_POLICY_IMM"
	TopologyDomainIsolation               = "Workload_Management_Isolation"
	EnvIsolationSharedStoragePolicyName   = "WORKLOAD_ISOLATION_SHARED_STORAGE_POLICY"
	EnvSharedZone2Zone4StoragePolicyName  = "SHARED_ZONE2_ZONE4_STORAGE_POLICY_IMM"
	EnvSharedZone2Zone4DatastoreUrl       = "SHARED_ZONE2_ZONE4_DATASTORE_URL"
)

// storage policy usages for storage quota validation
var UsageSuffixes = []string{
	"-pvc-usage",
	"-latebinding-pvc-usage",
	"-snapshot-usage",
	"-latebinding-snapshot-usage",
	"-vm-usage",
	"-latebinding-vm-usage",
}

const (
	StoragePolicyUsagePollInterval = 10 * time.Second
	StoragePolicyUsagePollTimeout  = 1 * time.Minute
)

// GetAndExpectEnvVar returns the value of an environment variable or fails the regression if it's not set.
func GetAndExpectEnvVar(varName string) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logger.GetLogger(ctx)

	varValue, exists := os.LookupEnv(varName)
	if !exists {
		log.Fatalf("Required environment variable not found: %s", varName)
	}
	return varValue
}

// GetAndExpectStringEnvVar parses a string from env variable.
func GetAndExpectStringEnvVar(varName string) string {
	varValue := os.Getenv(varName)
	gomega.Expect(varValue).NotTo(gomega.BeEmpty(), "ENV "+varName+" is not set")
	return varValue
}

// GetAndExpectIntEnvVar parses an int from env variable.
func GetAndExpectIntEnvVar(varName string) int {
	varValue := GetAndExpectStringEnvVar(varName)
	varIntValue, err := strconv.Atoi(varValue)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Error Parsing "+varName)
	return varIntValue
}

// GetBoolEnvVarOrDefault returns the boolean value of an environment variable or return default if it's not set
func GetBoolEnvVarOrDefault(varName string, defaultVal bool) bool {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		return defaultVal
	}

	varBoolValue, err := strconv.ParseBool(varValue)
	if err != nil {
		ctx := context.Background()
		log := logger.GetLogger(ctx)
		log.Warnf("Invalid boolean value for %s: '%s'. Using default: %v", varName, varValue, defaultVal)
		return defaultVal
	}

	return varBoolValue
}

// GetStringEnvVarOrDefault returns the string value of an environment variable or return default if it's not set
func GetStringEnvVarOrDefault(varName string, defaultVal string) string {
	varValue, exists := os.LookupEnv(varName)
	if !exists || strings.TrimSpace(varValue) == "" {
		return defaultVal
	}
	return varValue
}

/*
GetorIgnoreStringEnvVar, retrieves the value of an environment variable while logging
a warning if the variable is not set.
*/
func GetorIgnoreStringEnvVar(varName string) string {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		MissingEnvVars = append(MissingEnvVars, varName)
	}
	return varValue
}

// setClusterFlavor sets the boolean variables w.r.t the Cluster type.
func setClusterFlavor(clusterFlavor cnstypes.CnsClusterFlavor) {
	switch clusterFlavor {
	case cnstypes.CnsClusterFlavorWorkload:
		SupervisorCluster = true
	case cnstypes.CnsClusterFlavorGuest:
		GuestCluster = true
	default:
		VanillaCluster = true
	}

	// Check if the access mode is set for File volume setups
	kind := os.Getenv("ACCESS_MODE")
	if strings.TrimSpace(string(kind)) == "RWX" {
		RwxAccessMode = true
	}

	// Check if its the vcptocsi tesbed
	mode := os.Getenv("VCPTOCSI")
	if strings.TrimSpace(string(mode)) == "1" {
		Vcptocsi = true
	}
	//Check if its windows env
	workerNode := os.Getenv("WORKER_TYPE")
	if strings.TrimSpace(string(workerNode)) == "WINDOWS" {
		WindowsEnv = true
	}

	// Check if it's multiple supervisor cluster setup
	svcType := os.Getenv("SUPERVISOR_TYPE")
	if strings.TrimSpace(string(svcType)) == "MULTI_SVC" {
		MultipleSvc = true
	}

	//Check if it is multivc env
	topologyType := os.Getenv("TOPOLOGY_TYPE")
	if strings.TrimSpace(string(topologyType)) == "MULTI_VC" {
		Multivc = true
	}

	//Check if its stretched SVC testbed
	testbedType := os.Getenv("STRETCHED_SVC")
	if strings.TrimSpace(string(testbedType)) == "1" {
		StretchedSVC = true
	}
}

var (
	// reading port numbers for VC, Master VM and ESXi from export variables
	EnvVc1SshdPortNum       = "VC1_SSHD_PORT_NUM"
	EnvVc2SshdPortNum       = "VC2_SSHD_PORT_NUM"
	EnvVc3SshdPortNum       = "VC3_SSHD_PORT_NUM"
	EnvMasterIP1SshdPortNum = "MASTER_IP1_SSHD_PORT_NUM"
	EnvMasterIP2SshdPortNum = "MASTER_IP2_SSHD_PORT_NUM"
	EnvMasterIP3SshdPortNum = "MASTER_IP3_SSHD_PORT_NUM"
	EnvEsx1PortNum          = "ESX1_SSHD_PORT_NUM"
	EnvEsx2PortNum          = "ESX2_SSHD_PORT_NUM"
	EnvEsx3PortNum          = "ESX3_SSHD_PORT_NUM"
	EnvEsx4PortNum          = "ESX4_SSHD_PORT_NUM"
	EnvEsx5PortNum          = "ESX5_SSHD_PORT_NUM"
	EnvEsx6PortNum          = "ESX6_SSHD_PORT_NUM"
	EnvEsx7PortNum          = "ESX7_SSHD_PORT_NUM"
	EnvEsx8PortNum          = "ESX8_SSHD_PORT_NUM"
	EnvEsx9PortNum          = "ESX9_SSHD_PORT_NUM"
	EnvEsx10PortNum         = "ESX10_SSHD_PORT_NUM"

	// reading IPs for VC, Master VM and ESXi from export variables
	EnvVcIP1     = "VC_IP1"
	EnvVcIP2     = "VC_IP2"
	EnvVcIP3     = "VC_IP3"
	EnvMasterIP1 = "MASTER_IP1"
	EnvMasterIP2 = "MASTER_IP2"
	EnvMasterIP3 = "MASTER_IP3"
	EnvEsxIp1    = "ESX1_IP"
	EnvEsxIp2    = "ESX2_IP"
	EnvEsxIp3    = "ESX3_IP"
	EnvEsxIp4    = "ESX4_IP"
	EnvEsxIp5    = "ESX5_IP"
	EnvEsxIp6    = "ESX6_IP"
	EnvEsxIp7    = "ESX7_IP"
	EnvEsxIp8    = "ESX8_IP"
	EnvEsxIp9    = "ESX9_IP"
	EnvEsxIp10   = "ESX10_IP"

	// default port declaration for each IP
	VcIp1SshPortNum       = SshdPort
	VcIp2SshPortNum       = SshdPort
	VcIp3SshPortNum       = SshdPort
	EsxIp1PortNum         = SshdPort
	EsxIp2PortNum         = SshdPort
	EsxIp3PortNum         = SshdPort
	EsxIp4PortNum         = SshdPort
	EsxIp5PortNum         = SshdPort
	EsxIp6PortNum         = SshdPort
	EsxIp7PortNum         = SshdPort
	EsxIp8PortNum         = SshdPort
	EsxIp9PortNum         = SshdPort
	EsxIp10PortNum        = SshdPort
	K8sMasterIp1PortNum   = SshdPort
	K8sMasterIp2PortNum   = SshdPort
	K8sMasterIp3PortNum   = SshdPort
	DefaultVcAdminPortNum = "443"

	// global variables declared
	EsxIp1             = ""
	EsxIp2             = ""
	EsxIp3             = ""
	EsxIp4             = ""
	EsxIp5             = ""
	EsxIp6             = ""
	EsxIp7             = ""
	EsxIp8             = ""
	EsxIp9             = ""
	EsxIp10            = ""
	VcAddress          = ""
	VcAddress2         = ""
	VcAddress3         = ""
	MasterIP1          = ""
	MasterIP2          = ""
	MasterIP3          = ""
	IpPortMap          = make(map[string]string)
	MissingEnvVars     []string
	DefaultlocalhostIP = "127.0.0.1"
)

/*
The setSShdPort function dynamically configures SSH port mappings for a vSphere test environment by reading
environment variables and adapting to the network type and topology.
It sets up SSH access to vCenter servers, ESXi hosts, and Kubernetes masters based on the environment configuration.
*/
func safeInsertToMap(key, value string) {
	if key != "" && value != "" {
		IpPortMap[key] = value
	}
}

func setSShdPort() {
	VcAddress = GetAndExpectEnvVar(EnvVcIP1)
	isPrivateNetwork := GetBoolEnvVarOrDefault("IS_PRIVATE_NETWORK", false)

	if Multivc {
		VcAddress2 = GetAndExpectEnvVar(EnvVcIP2)
		VcAddress3 = GetAndExpectEnvVar(EnvVcIP3)
	}

	if isPrivateNetwork {
		if Multivc {
			VcIp2SshPortNum = GetorIgnoreStringEnvVar(EnvVc2SshdPortNum)
			VcIp3SshPortNum = GetorIgnoreStringEnvVar(EnvVc3SshdPortNum)

			safeInsertToMap(VcAddress2, VcIp2SshPortNum)
			safeInsertToMap(VcAddress3, VcIp3SshPortNum)
		}

		// reading masterIP and its port number
		MasterIP1 = GetorIgnoreStringEnvVar(EnvMasterIP1)
		MasterIP2 = GetorIgnoreStringEnvVar(EnvMasterIP2)
		MasterIP3 = GetorIgnoreStringEnvVar(EnvMasterIP3)
		K8sMasterIp1PortNum = GetorIgnoreStringEnvVar(EnvMasterIP1SshdPortNum)
		K8sMasterIp2PortNum = GetorIgnoreStringEnvVar(EnvMasterIP2SshdPortNum)
		K8sMasterIp3PortNum = GetorIgnoreStringEnvVar(EnvMasterIP3SshdPortNum)

		VcIp1SshPortNum = GetorIgnoreStringEnvVar(EnvVc1SshdPortNum)

		// reading esxi ip and its port
		EsxIp1 = GetorIgnoreStringEnvVar(EnvEsxIp1)
		EsxIp1PortNum = GetorIgnoreStringEnvVar(EnvEsx1PortNum)
		EsxIp2PortNum = GetorIgnoreStringEnvVar(EnvEsx2PortNum)
		EsxIp3PortNum = GetorIgnoreStringEnvVar(EnvEsx3PortNum)
		EsxIp4PortNum = GetorIgnoreStringEnvVar(EnvEsx4PortNum)
		EsxIp5PortNum = GetorIgnoreStringEnvVar(EnvEsx5PortNum)
		EsxIp6PortNum = GetorIgnoreStringEnvVar(EnvEsx6PortNum)
		EsxIp7PortNum = GetorIgnoreStringEnvVar(EnvEsx7PortNum)
		EsxIp8PortNum = GetorIgnoreStringEnvVar(EnvEsx8PortNum)
		EsxIp9PortNum = GetorIgnoreStringEnvVar(EnvEsx9PortNum)
		EsxIp10PortNum = GetorIgnoreStringEnvVar(EnvEsx10PortNum)

		EsxIp2 = GetorIgnoreStringEnvVar(EnvEsxIp2)
		EsxIp3 = GetorIgnoreStringEnvVar(EnvEsxIp3)
		EsxIp4 = GetorIgnoreStringEnvVar(EnvEsxIp4)
		EsxIp5 = GetorIgnoreStringEnvVar(EnvEsxIp5)
		EsxIp6 = GetorIgnoreStringEnvVar(EnvEsxIp6)
		EsxIp7 = GetorIgnoreStringEnvVar(EnvEsxIp7)
		EsxIp8 = GetorIgnoreStringEnvVar(EnvEsxIp8)
		EsxIp9 = GetorIgnoreStringEnvVar(EnvEsxIp9)
		EsxIp10 = GetorIgnoreStringEnvVar(EnvEsxIp10)

		safeInsertToMap(VcAddress, VcIp1SshPortNum)
		safeInsertToMap(MasterIP1, K8sMasterIp1PortNum)
		safeInsertToMap(MasterIP2, K8sMasterIp2PortNum)
		safeInsertToMap(MasterIP3, K8sMasterIp3PortNum)
		safeInsertToMap(EsxIp1, EsxIp1PortNum)
		safeInsertToMap(EsxIp2, EsxIp2PortNum)
		safeInsertToMap(EsxIp3, EsxIp3PortNum)
		safeInsertToMap(EsxIp4, EsxIp4PortNum)
		safeInsertToMap(EsxIp5, EsxIp5PortNum)
		safeInsertToMap(EsxIp6, EsxIp6PortNum)
		safeInsertToMap(EsxIp7, EsxIp7PortNum)
		safeInsertToMap(EsxIp8, EsxIp8PortNum)
		safeInsertToMap(EsxIp9, EsxIp9PortNum)
		safeInsertToMap(EsxIp10, EsxIp10PortNum)
	}

	if len(MissingEnvVars) > 0 {
		ctx := context.Background()
		log := logger.GetLogger(ctx)
		log.Warnf("Missing environment variables: %v", strings.Join(MissingEnvVars, ", "))
	}
}
