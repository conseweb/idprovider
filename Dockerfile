FROM ckeyer/obc:run

COPY bundles/idprovider /usr/local/bin/
COPY idprovider.yaml /usr/local/bin/

WORKDIR /usr/local/bin/
EXPOSE 7054

CMD ["idprovider"]