# Google Cloud DynDNS

Gcloud-dyndns is a Python script to update DNS records in Google cloud DNS. It can get the IP address from a network interface, URL or a file and keeps the configured registries up to date.

It supports a single IPv4 address and an IPv6 delegated prefix.

## Usage

The script depends on several python packages, see the `requirements.txt` file.

Create a yaml configuration file using `gcloud-dyndns.yml.example` as a reference of the different supported options, and run it indicating the configuration file with `--conf-file`.
