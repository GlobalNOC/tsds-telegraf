FROM telegraf:1.17

WORKDIR /

RUN echo 'deb http://deb.debian.org/debian/ buster main contrib non-free\ndeb http://deb.debian.org/debian/ buster-updates main contrib non-free\ndeb http://security.debian.org/debian-security buster/updates main contrib non-free' > /etc/apt/sources.list

RUN apt-get update \
    && apt-get install -y python3 python3-pip snmp snmp-mibs-downloader\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /
RUN pip3 install -r requirements.txt

COPY bin/tsds-output.py /usr/bin/
COPY conf/dummy.conf /etc/telegraf/telegraf.conf
ADD VERSION .

ENTRYPOINT [ "/usr/bin/telegraf"]
CMD [ "-config", "/etc/telegraf/telegraf.conf", "-config-directory", "/etc/telegraf/conf.d" ]
