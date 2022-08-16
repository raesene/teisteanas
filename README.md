# Client Certificate Creator

This is just a small program that can be used to create and approve a Client Signing Request in a Kubernetes cluster and then create a new kubeconfig based on that approved certificate.

The code is heavily based on [this article](https://medium.com/@elfakharany/automate-kubernetes-user-creation-using-the-native-go-client-e2d20dcdc9de) with some modifications for new CSR API versions and things I needed for this example.

It works based on the current context in a provided Kubeconfig file. If no file is provided then $HOME/.kube/config is used.

There are three command line parameters

* `--username` - The username for the certificate. This one is mandatory.
* `--group` - The group for the certificate. Defaults to none.
* `--kubeconfig` - The kubeconfig to use to connect to the cluster.

The Kubeconfig file will have the filename of the user provided.