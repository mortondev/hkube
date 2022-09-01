/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package apply

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hetznercloud/hcloud-go/hcloud"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	utilpointer "k8s.io/utils/pointer"
)

// var host string
// serversCmd represents the servers command
var ApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Create Kubernetes cluster",
	Run: func(cmd *cobra.Command, args []string) {

		// Hetzner
		hclient := hcloud.NewClient(hcloud.WithToken(viper.GetString("hetzner_token")))
		masters := createServers(hclient, true)

		setupK3s(masters)

		kubeconfig, err := saveKubeconfig(masters[0])
		if err != nil {
			log.Println(err)
		}

		config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
		if err != nil {
			fmt.Println(err)
			return
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Println(err)
			return
		}

		deployCloudController(clientset)

		log.Println("Cluster setup is complete")

	},
}

type UserData struct {
	PackageUpdate  bool     `yaml:"package_update"`
	PackageUpgrade bool     `yaml:"package_upgrade"`
	Packages       []string `yaml:"packages"`
	Runcmd         []string `yaml:"runcmd"`
}

func createServers(hclient *hcloud.Client, isMaster bool) []*hcloud.Server {
	log.Printf("Applying cluster %s...", viper.GetString("cluster_name"))

	var instanceType string
	var instanceCount int
	if isMaster {
		instanceType = viper.GetString("masters.instance_type")
		instanceCount = viper.GetInt("masters.instance_count")
	} else {
		instanceType = viper.GetString("agents.instance_type")
		instanceCount = viper.GetInt("agents.instance_count")
	}

	serverType, _, err := hclient.ServerType.GetByName(context.Background(), instanceType)
	if err != nil {
		log.Printf("ERROR: error retrieving server: %s\n", err)
	}

	network, _, err := hclient.Network.Get(context.Background(), viper.GetString("cluster_name"))
	if err != nil {
		log.Printf("ERROR: retrieving network: %s\n", err)
	}

	image, _, err := hclient.Image.Get(context.Background(), "ubuntu-22.04")
	if err != nil {
		log.Printf("ERROR: retrieving image: %s\n", err)
	}

	sshFingerprint, err := sshKeyFingerprint()
	if err != nil {
		log.Printf("ERROR: retrieving ssh key fingerprint: %s\n", err)
	}

	sshkey, _, err := hclient.SSHKey.GetByFingerprint(context.Background(), sshFingerprint)
	if err != nil {
		log.Printf("ERROR: retrieving fingerprint: %s\n", err)
	}

	placementGroup, _, err := hclient.PlacementGroup.GetByName(context.Background(), viper.GetString("cluster_name"))
	if err != nil {
		log.Printf("ERROR: retrieving placement group: %s\n", err)
	}
	if placementGroup == nil {
		createRes, _, err := hclient.PlacementGroup.Create(context.Background(), hcloud.PlacementGroupCreateOpts{
			Name: viper.GetString("cluster_name"),
			Type: hcloud.PlacementGroupType("spread"),
		})
		if err != nil {
			log.Printf("ERROR: creating placement group: %s\n", err)
		} else {
			placementGroup = createRes.PlacementGroup
		}
	}

	cluster_name := viper.GetString("cluster_name")
	location := viper.GetString("location")
	userData := UserData{
		PackageUpdate:  true,
		PackageUpgrade: true,
		Packages:       []string{"fail2ban", "ufw", "wireguard"},
		Runcmd: []string{
			`crontab -l > /etc/cron_bkp`,
			`echo "@reboot echo true > /etc/ready" >> /etc/cron_bkp`,
			`crontab /etc/cron_bkp`,
			`printf "[sshd]\nenabled = true\nbanaction = iptables-multiport" > /etc/fail2ban/jail.local`,
			`systemctl enable fail2ban`,
			// `ufw allow OpenSSH`,
			// `ufw enable`,
			`sed -i -e '/^PermitRootLogin/s/^.*$/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config`,
			`sed -i -e '/^PasswordAuthentication/s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config`,
			`sed -i -e '/^X11Forwarding/s/^.*$/X11Forwarding no/' /etc/ssh/sshd_config`,
			`sed -i -e '/^#MaxAuthTries/s/^.*$/MaxAuthTries 2/' /etc/ssh/sshd_config`,
			`sed -i -e '/^#AllowTcpForwarding/s/^.*$/AllowTcpForwarding no/' /etc/ssh/sshd_config`,
			`sed -i -e '/^#AllowAgentForwarding/s/^.*$/AllowAgentForwarding no/' /etc/ssh/sshd_config`,
			`sed -i -e '/^#AuthorizedKeysFile/s/^.*$/AuthorizedKeysFile .ssh\/authorized_keys/' /etc/ssh/sshd_config`,
			`systemctl restart sshd`,
			`systemctl stop systemd-resolved`,
			`systemctl disable systemd-resolved`,
			`rm /etc/resolv.conf`,
			`echo 'nameserver 1.1.1.1' > /etc/resolv.conf`,
			`echo 'nameserver 1.0.0.1' >> /etc/resolv.conf`,
			`reboot`,
		},
	}
	userDataYaml, err := yaml.Marshal(&userData)
	if err != nil {
		log.Printf("Error writing yaml: %s\n", err)
	}

	yamlString := string(userDataYaml)
	cloudConfig := fmt.Sprintf("#cloud-config\n%s", yamlString)

	var servers []*hcloud.Server
	for i := 1; i <= instanceCount; i++ {
		var serverName string
		if isMaster {
			serverName = fmt.Sprintf("%s-%s-master%d", cluster_name, instanceType, i)
		} else {
			serverName = fmt.Sprintf("%s-%s-agent%d", cluster_name, instanceType, i)
		}

		// Check if server already exists
		var server *hcloud.Server
		server, _, err = hclient.Server.GetByName(context.Background(), serverName)
		if err != nil {
			log.Printf("ERROR %s: %s\n", err, serverName)
		}
		if server != nil {
			log.Printf("Server %s (%s) already exists", server.Name, server.PublicNet.IPv4.IP)
			servers = append(servers, server)
			continue
		}

		// Create server
		log.Printf("Creating server %s...", serverName)
		createRes, _, err := hclient.Server.Create(context.Background(), hcloud.ServerCreateOpts{
			Name:           serverName,
			Image:          &hcloud.Image{ID: image.ID},
			ServerType:     &hcloud.ServerType{ID: serverType.ID},
			SSHKeys:        []*hcloud.SSHKey{{ID: sshkey.ID}},
			Location:       &hcloud.Location{Name: location},
			Labels:         map[string]string{"cluster": cluster_name, "role": "master"},
			Networks:       []*hcloud.Network{{ID: network.ID}},
			PlacementGroup: &hcloud.PlacementGroup{ID: placementGroup.ID},
			UserData:       cloudConfig,
		})

		if err != nil {
			log.Printf("ERROR: %s: %s\n", err, serverName)
		} else if createRes.Server == nil {
			log.Printf("no server\n")
		} else if createRes.RootPassword != "" {
			log.Printf("ERROR: expected no root password, got: %v\n", createRes.RootPassword)
		} else if len(createRes.NextActions) != 2 || createRes.NextActions[0].Command != "start_server" {
			log.Printf("ERROR: unexpected next actions: %v\n", createRes.NextActions)
			for _, na := range createRes.NextActions {
				log.Printf(na.Command)
			}
		}

		// Get server we just created as properties are not always set
		server, _, err = hclient.Server.Get(context.Background(), fmt.Sprint(createRes.Server.ID))
		if err != nil {
			log.Printf("ERROR: %s: %s\n", err, serverName)
		}

		log.Printf("Server %s (%s) created", server.Name, server.PublicNet.IPv4.IP)
		servers = append(servers, server)

	}

	for _, s := range servers {
		waitForServerReady(s)
	}

	return servers
}

func waitForServerReady(server *hcloud.Server) {
	var ready = false
	for !ready {
		log.Printf("Waiting for %s (%s) to be ready...\n", server.Name, server.PublicNet.IPv4.IP)
		commandResult, _ := sshExecuteCommand("cat /etc/ready", server.PublicNet.IPv4.IP.String(), false)
		output := string(commandResult.StdOut)
		if strings.Contains(output, "true") {
			ready = true
			log.Printf("%s (%s) is ready\n", server.Name, server.PublicNet.IPv4.IP)
			break
		}

		time.Sleep(10 * time.Second)
	}
}

func sshKeyFingerprint() (string, error) {
	key, err := ioutil.ReadFile("/home/james/.ssh/id_rsa")
	if err != nil {
		return "", err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", err
	}

	return ssh.FingerprintLegacyMD5(signer.PublicKey()), nil
}

func loadPrivateKey() (ssh.AuthMethod, error) {
	key, err := ioutil.ReadFile("/home/james/.ssh/id_rsa")
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	ssh.FingerprintLegacyMD5(signer.PublicKey())
	return ssh.PublicKeys(signer), nil
}

type CommandResult struct {
	StdOut []byte
	StdErr []byte
}

func sshExecuteCommand(command string, host string, stream bool) (CommandResult, error) {
	port := "22"
	user := "root"

	authMethod, err := loadPrivateKey()

	if err != nil {
		return CommandResult{}, err
	}

	// ssh client config
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// connect
	client, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		return CommandResult{}, err
	}
	defer client.Close()

	// start session
	sess, err := client.NewSession()
	if err != nil {
		return CommandResult{}, err
	}
	defer sess.Close()

	//setup standard out and error
	// uses writer interface
	wg := sync.WaitGroup{}

	output := bytes.Buffer{}

	var stdOutWriter io.Writer
	if stream {
		stdOutWriter = io.MultiWriter(os.Stdout, &output)
	} else {
		stdOutWriter = &output
	}

	sessStdOut, err := sess.StdoutPipe()
	if err != nil {
		return CommandResult{}, err
	}

	wg.Add(1)
	go func() {
		io.Copy(stdOutWriter, sessStdOut)
		wg.Done()
	}()

	errOutput := bytes.Buffer{}

	var stdErrWriter io.Writer
	if stream {
		stdErrWriter = io.MultiWriter(os.Stderr, &errOutput)
	} else {
		stdErrWriter = &errOutput
	}
	sessStdErr, err := sess.StderrPipe()
	if err != nil {
		return CommandResult{}, err
	}

	wg.Add(1)
	go func() {
		io.Copy(stdErrWriter, sessStdErr)
		wg.Done()
	}()

	// run single command
	err = sess.Run(command)
	wg.Wait()

	if err != nil {
		return CommandResult{}, err
	}

	return CommandResult{
		StdOut: output.Bytes(),
		StdErr: errOutput.Bytes(),
	}, nil
}

func k3sInstallScript(server *hcloud.Server, api string, token string) string {
	installArgs := []string{}

	if strings.HasSuffix(server.Name, "master1") {
		installArgs = append(installArgs, `--cluster-init`)
	} else {
		installArgs = append(installArgs, fmt.Sprintf(`--server https://%s:6443`, api))
	}

	installArgs = append(installArgs, `--disable-cloud-controller`)
	installArgs = append(installArgs, `--disable servicelb`)
	installArgs = append(installArgs, `--disable traefik`)
	installArgs = append(installArgs, `--disable local-storage`)
	installArgs = append(installArgs, `--disable metrics-server`)
	installArgs = append(installArgs, `--write-kubeconfig-mode=644`)
	installArgs = append(installArgs, `--node-name="$(hostname -f)"`)
	installArgs = append(installArgs, `--cluster-cidr=10.244.0.0/16`)
	installArgs = append(installArgs, `--etcd-expose-metrics=true`)
	installArgs = append(installArgs, `--kube-controller-manager-arg="bind-address=0.0.0.0"`)
	installArgs = append(installArgs, `--kube-proxy-arg="metrics-bind-address=0.0.0.0"`)
	installArgs = append(installArgs, `--kube-scheduler-arg="bind-address=0.0.0.0"`)
	installArgs = append(installArgs, `--kubelet-arg="cloud-provider=external"`)
	installArgs = append(installArgs, `--advertise-address=$(hostname -I | awk '{print $2}')`)
	installArgs = append(installArgs, `--node-ip=$(hostname -I | awk '{print $2}')`)
	installArgs = append(installArgs, `--node-external-ip=$(hostname -I | awk '{print $1}')`)
	installArgs = append(installArgs, `--tls-san=$(hostname -I | awk '{print $1}')`)
	installArgs = append(installArgs, `--tls-san=$(hostname -I | awk '{print $2}')`)

	fi := findFlannelInterface(server)
	installArgs = append(installArgs, fmt.Sprintf(`--flannel-iface=%s`, fi))
	installArgs = append(installArgs, `--flannel-backend=wireguard-native`)

	installArgsCmdline := " "
	for _, a := range installArgs {
		installArgsCmdline += a + " "
	}

	var installCmd string
	if len(token) == 0 {
		installCmd = fmt.Sprintf(`curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.24.4+k3s1" INSTALL_K3S_EXEC="server %s" sh -`, installArgsCmdline)
	} else {
		installCmd = fmt.Sprintf(`curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.24.4+k3s1" K3S_TOKEN="%s" INSTALL_K3S_EXEC="server %s" sh -`, token, installArgsCmdline)
	}
	return installCmd
}

func setupK3s(servers []*hcloud.Server) {

	// First server = API Server
	apiServer := servers[0].PublicNet.IPv4.IP.String()
	nodeToken := ""

	for i, server := range servers {
		installCmd := k3sInstallScript(server, apiServer, nodeToken)
		sshExecuteCommand(installCmd, server.PublicNet.IPv4.IP.String(), true)

		if i == 0 {
			result, _ := sshExecuteCommand("cat /var/lib/rancher/k3s/server/node-token", server.PublicNet.IPv4.IP.String(), false)
			nodeToken = strings.TrimSpace(string(result.StdOut))
		}
	}

	// time.Sleep(10 * time.Second)
}

func findFlannelInterface(server *hcloud.Server) string {
	result, _ := sshExecuteCommand("lscpu | grep Vendor", server.PublicNet.IPv4.IP.String(), false)

	if strings.Contains(string(result.StdOut), "Intel") {
		return "ens10"
	} else {
		return "enp7s0"
	}
}

// Get k3s kubeconfig from server
func saveKubeconfig(server *hcloud.Server) ([]byte, error) {
	commandResult, err := sshExecuteCommand("cat /etc/rancher/k3s/k3s.yaml", server.PublicNet.IPv4.IP.String(), false)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	kubeconfig := string(commandResult.StdOut)
	kubeconfig = strings.Replace(kubeconfig, "127.0.0.1", server.PublicNet.IPv4.IP.String(), -1)
	kubeconfig = strings.Replace(kubeconfig, "default", viper.GetString("cluster_name"), -1)

	// Save to file
	err = ioutil.WriteFile("kubeconfig", []byte(kubeconfig), 0644)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return []byte(kubeconfig), nil
}

func deployCloudController(clientset *kubernetes.Clientset) {
	log.Println("Deploying cloud controller")

	api := clientset.CoreV1()
	// print pods
	// pods, err := api.Pods("kube-system").List(context.Background(), metav1.ListOptions{})
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
	// for _, pod := range pods.Items {
	// 	fmt.Println(" - " + pod.Name)
	// }

	// Create hcloud secret
	api.Secrets("kube-system").Create(context.Background(), &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "hcloud",
		},
		StringData: map[string]string{
			"network": viper.GetString("cluster_name"),
			"token":   viper.GetString("hetzner_token"),
		},
	}, metav1.CreateOptions{})

	api.ServiceAccounts("kube-system").Create(context.Background(), &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cloud-controller-manager",
			Namespace: "kube-system",
		},
	}, metav1.CreateOptions{})

	rbac := clientset.RbacV1()

	rbac.ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:cloud-controller-manager",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "cloud-controller-manager",
				Namespace: "kube-system",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
	}, metav1.CreateOptions{})

	deployment := clientset.AppsV1().Deployments("kube-system")
	deployment.Create(context.Background(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hcloud-cloud-controller-manager",
			Namespace: "kube-system",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             utilpointer.Int32Ptr(1),
			RevisionHistoryLimit: utilpointer.Int32Ptr(2),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "hcloud-cloud-controller-manager",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "hcloud-cloud-controller-manager",
					},
				},
				Spec: v1.PodSpec{
					ServiceAccountName: "cloud-controller-manager",
					DNSPolicy:          v1.DNSDefault,
					PriorityClassName:  "system-cluster-critical",
					Tolerations: []v1.Toleration{
						{
							Key:    "node.cloudprovider.kubernetes.io/uninitialized",
							Value:  "true",
							Effect: v1.TaintEffectNoSchedule,
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: v1.TolerationOpExists,
						},
						{
							Key:      "node-role.kubernetes.io/master",
							Effect:   v1.TaintEffectNoSchedule,
							Operator: v1.TolerationOpExists,
						},
						{
							Key:      "node-role.kubernetes.io/control-plane",
							Effect:   v1.TaintEffectNoSchedule,
							Operator: v1.TolerationOpExists,
						},
						{
							Key:    "node.kubernetes.io/not-ready",
							Effect: v1.TaintEffectNoSchedule,
						},
					},
					HostNetwork: true,
					Containers: []v1.Container{
						{
							Image: "hetznercloud/hcloud-cloud-controller-manager:v1.9.1",
							Name:  "hcloud-cloud-controller-manager",
							Command: []string{
								"/bin/hcloud-cloud-controller-manager",
								"--cloud-provider=hcloud",
								"--leader-elect=false",
								"--allow-untagged-cloud",
								"--allocate-node-cidrs=true",
								"--cluster-cidr=10.244.0.0/16",
							},
							Resources: v1.ResourceRequirements{
								Requests: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("100m"),
									v1.ResourceMemory: resource.MustParse("50Mi"),
								},
							},
							Env: []v1.EnvVar{
								{
									Name: "NODE_NAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "spec.nodeName",
										},
									},
								},
								{
									Name: "HCLOUD_TOKEN",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: "hcloud",
											},
											Key: "token",
										},
									},
								},
								{
									Name: "HCLOUD_NETWORK",
									ValueFrom: &v1.EnvVarSource{
										SecretKeyRef: &v1.SecretKeySelector{
											LocalObjectReference: v1.LocalObjectReference{
												Name: "hcloud",
											},
											Key: "network",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
}

func init() {
	ApplyCmd.Flags().StringP("host", "", "", "Remote host to SSH into")
	viper.BindPFlag("host", ApplyCmd.Flags().Lookup("host"))

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
}
