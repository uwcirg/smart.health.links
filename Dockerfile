FROM denoland/deno:1.25.2
EXPOSE 8000
WORKDIR /app
USER root
RUN apt-get update && \
    apt-get install -y sqlite3 gosu && \
    #remove cached package lists
    rm -rf /var/lib/apt/lists/* && \
    # sanity check
    gosu nobody true
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN chown -R deno:deno /app
COPY --chown=deno deps.ts .
RUN deno cache deps.ts
COPY --chown=deno . .
RUN deno cache server.ts
ENTRYPOINT ["/entrypoint.sh"]
#TODO review logging docs RUN mkdir -p /var/tmp/log
CMD ["deno", "run", "--allow-all", "server.ts"]
