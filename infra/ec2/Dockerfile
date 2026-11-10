FROM localstack/ami-ubuntu:22.04

RUN apt-get update && apt-get install -y openssh-server sudo curl net-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh /home/ubuntu/.ssh

# Create ubuntu user if not exists
RUN id ubuntu >/dev/null 2>&1 || useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu

# Set simple passwords
RUN echo 'root:root' | chpasswd && echo 'ubuntu:ubuntu' | chpasswd

# Configure sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && echo "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config \
    && echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Copy authorized_keys if provided
COPY authorized_keys* /root/.ssh/authorized_keys
RUN if [ -f /root/.ssh/authorized_keys ]; then \
      cp /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys && \
      chown -R ubuntu:root /home/ubuntu/.ssh && \
      chmod 600 /home/ubuntu/.ssh/authorized_keys && \
      chmod 600 /root/.ssh/authorized_keys; \
    fi

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]

