FROM sagemath/sagemath:10.7

USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        gcc \
        gdb \
        socat \
        libcap2-bin && \
    setcap cap_sys_ptrace+ep /usr/bin/gdb && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf && \
    useradd -M -s /usr/sbin/nologin target
RUN chmod 777 /home/ctf && \
    mkdir -p /opt/ctf && \
    chown root:root /opt/ctf && \
    chmod 755 /opt/ctf
ENV HOME=/home/sage
ENV PATH=/home/sage/sage/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /home/sage
COPY wut.c /home/ctf/wut.c
COPY chall.py /opt/ctf/chall.py

RUN gcc -Wall -Wextra -O0 -g -fPIE -pie -Wl,-z,relro,-z,now -o /home/ctf/tes /home/ctf/wut.c && \
    chown target:target /home/ctf/tes && \
    chmod 2755 /home/ctf/tes && \
    chown root:root /home/ctf/wut.c /opt/ctf/chall.py && \
    chmod 644 /home/ctf/wut.c /opt/ctf/chall.py && \
    sage_venv="$(find /home/sage/sage/local/var/lib/sage -maxdepth 1 -type d -name 'venv-python*' | head -n 1)" && \
    site_packages="$(find "$sage_venv/lib" -type d -path '*/site-packages' | head -n 1)" && \
    test -n "$sage_venv" && test -n "$site_packages" && \
    find "$site_packages" -type d -exec chmod a-w {} + && \
    find "$site_packages" -type f \( -name '*.py' -o -name '*.pth' \) -exec chmod a-w {} + && \
    for target in /home/sage/sage/sage /home/sage/sage/src/bin/sage /home/sage/sage/src/bin/sage-python /home/sage/sage/src/bin/sage-run; do \
        test ! -e "$target" || chmod a-w "$target"; \
    done && \
    test ! -e /home/sage/sage/local/lib/gap/sysinfo.gap || chmod a-w /home/sage/sage/local/lib/gap/sysinfo.gap /home/sage/sage/local/lib/gap && \
    test ! -d "$sage_venv/share/cysignals" || chmod -R a-w "$sage_venv/share/cysignals" && \
    ln -s "$sage_venv/bin/cysignals-CSI" /opt/ctf/cysignals-CSI && \
    mkdir -p /home/ctf/.sage && \
    chown -R ctf:ctf /home/ctf/.sage && \
    printf 'COMPFEST18{test_flag}\n' > /home/ctf/flag.txt && \
    chown target:target /home/ctf/flag.txt && \
    chmod 440 /home/ctf/flag.txt

USER sage

WORKDIR /home/ctf
EXPOSE 8080
ENTRYPOINT []
CMD ["socat", "TCP-LISTEN:8080,reuseaddr,fork", "EXEC:'/usr/bin/sage -python /opt/ctf/chall.py',pty,stderr"]
