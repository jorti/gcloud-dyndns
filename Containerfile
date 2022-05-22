ARG FEDORA_ARCH=x86_64
ARG FEDORA_VERSION=36
FROM registry.fedoraproject.org/fedora:${FEDORA_VERSION}-${FEDORA_ARCH}

RUN dnf update -y --setopt=install_weak_deps=False --nodocs && \
    dnf install -y --setopt=install_weak_deps=False --nodocs python3-google-cloud-dns python3-netifaces python3-pyyaml curl && \
    dnf clean all && \
    useradd -s /sbin/nologin -d / -c "Google cloud DynDNS updater" dyndns

COPY gcloud-dyndns.py /usr/local/bin/gcloud-dyndns.py
LABEL maintainer="Juan Orti Alcaine <jortialc@redhat.com>" \
      description="Google Cloud DynDNS"
USER dyndns:dyndns
CMD ["/usr/local/bin/gcloud-dyndns.py", "--conf-file=/etc/gcloud-dyndns/gcloud-dyndns.yml"]
