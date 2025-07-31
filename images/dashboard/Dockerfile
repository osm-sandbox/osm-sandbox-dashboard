FROM python:3.9
ARG TARGETARCH
ARG KUBECTL_VERSION=v1.30.1
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/
RUN kubectl version --client
RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3  && chmod 700 get_helm.sh && ./get_helm.sh
COPY ./src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
EXPOSE 8000
COPY ./src/ /app/
WORKDIR /app
CMD ["bash", "/app/start.sh"]
