FROM kalilinux/kali-rolling:latest

# Update + ferramentas Kali essenciais para nossos adapters.
# Mantemos enxuto: NÃO usamos kali-linux-large (vai a >12GB).
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl wget jq git \
        nmap masscan \
        ffuf gobuster dirsearch \
        sqlmap nikto \
        amass \
        whois dnsutils \
        openssh-client \
        python3 python3-pip python3-venv \
        ruby \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery suite via go (instala via binário pre-built)
ARG TARGETARCH=amd64
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.6_linux_${TARGETARCH}.zip -o /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm /tmp/subfinder.zip || echo "subfinder install fallback"
RUN curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.9_linux_${TARGETARCH}.zip -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin/ \
    && rm /tmp/httpx.zip || echo "httpx install fallback"
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.5_linux_${TARGETARCH}.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip || echo "nuclei install fallback"
RUN curl -sL https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.3.3_linux_${TARGETARCH}.zip -o /tmp/naabu.zip \
    && unzip /tmp/naabu.zip -d /usr/local/bin/ \
    && rm /tmp/naabu.zip || echo "naabu install fallback"

# Secret-finding tools
RUN curl -sL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin/ gitleaks || true
RUN curl -sL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_3.83.7_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ trufflehog || true

# Cloud / IaC
RUN pip install --break-system-packages --no-cache-dir \
        checkov \
        dnstwist \
    || pip install --no-cache-dir checkov dnstwist

# Trivy CLI (cliente — server roda em outro container)
RUN curl -sL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.57.1_Linux-64bit.tar.gz | tar -xz -C /usr/local/bin/ trivy || true

# kube-bench
RUN curl -sL https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_0.10.5_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ kube-bench || true

# Templates do nuclei
RUN nuclei -update-templates || true

# gvm-tools (cliente Greenbone GMP)
RUN pip install --break-system-packages --no-cache-dir gvm-tools python-gvm || pip install --no-cache-dir gvm-tools python-gvm

WORKDIR /workspace

# Pequena verificação de bins instalados (diagnóstico)
RUN echo "Installed:" \
    && (nmap --version | head -1) \
    && (nuclei -version 2>&1 | head -1 || true) \
    && (gitleaks version 2>&1 | head -1 || true) \
    && (trufflehog --version 2>&1 | head -1 || true) \
    && (dnstwist --version 2>&1 | head -1 || true) \
    && (trivy --version 2>&1 | head -1 || true)
