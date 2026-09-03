# The OpenSSH server the interop tests run against.
#
# Built here rather than pulled from a general purpose image so the offered
# algorithms are known exactly. When a test fails, that leaves only one
# explanation: this client got the algorithm wrong.
FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh dartssh2 \
    && echo 'dartssh2:dartssh2-test-password' | chpasswd \
    && adduser -D -s /bin/sh dartssh2-nopty \
    && echo 'dartssh2-nopty:dartssh2-test-password' | chpasswd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 2222

CMD ["/usr/sbin/sshd", "-D", "-e"]
