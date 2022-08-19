# Client Certificate Creator

This is just a small program that can be used to create and approve a Client Signing Request in a Kubernetes cluster and then create a new kubeconfig based on that approved certificate.

The code is heavily based on [this article](https://medium.com/@elfakharany/automate-kubernetes-user-creation-using-the-native-go-client-e2d20dcdc9de) with some modifications for new CSR API versions and things I needed for this example. Setting `expirationSeconds` will add that to the CSR. Kubernetes servers tend to have upper limits for how long they'll issue a certificate for (although these times vary wildly), and generally `600` is the lower bound for what you can set.

It connects to a cluster based on the current context in a provided Kubeconfig file. If no file is provided then $HOME/.kube/config is used.

There are five command line parameters :-

* `--username` - The username for the certificate. (MANDATORY)
* `--group` - The group for the certificate. Defaults to none. (OPTIONAL)
* `--kubeconfig` - The kubeconfig to use to connect to the cluster. Default is `$HOME/.kube/config` (OPTIONAL)
* `--output-file` - Filename for the output kubeconfig file. Default is [username].config (OPTIONAL)
* `--expirationSeconds` - Number of seconds for the certificate to be valid.  If not specified this will take the server's default setting.  (OPTIONAL)

## Known Limitations

- This won't work on EKS clusters because they don't issue certificates for Client authentication.
- This won't work with clusters earlier than 1.19 as we're using v1 of the CSR API which was issued then.