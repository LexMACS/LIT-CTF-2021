#replace [challenge] and [version] with challenge elf name and libc version

FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

COPY flag.txt /home/user/
COPY [challenge] /home/user/
COPY libc-[version].so /home/user/
COPY ld-[version].so /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:035cc67b4dfd74077a8a305321b17854481308dec5af28fc8ad1d6c75d729340

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/[challenge]"
