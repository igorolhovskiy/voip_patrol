FROM python:3.7-buster

RUN echo "installing dependencies" \
	&& apt-get update && apt-get install -y build-essential libcurl4-openssl-dev cmake pkg-config libasound2-dev \
	&& apt-get -y install libssl-dev git libopus-dev libsrtp2-dev

RUN echo "building VoIP Patrol" \
	&& mkdir /git && cd /git && git clone -b srtp_add https://github.com/igorolhovskiy/voip_patrol.git \
	&& cd voip_patrol \
	&& git submodule update --init \
	&& cd pjproject && ./configure --disable-libwebrtc --disable-opencore-amr \
	&& cp ../include/config_site.h  pjlib/include/pj/config_site.h \
	&& make dep && make && make install \
	&& cd .. && cmake CMakeLists.txt && make

RUN ln -s /git/voip_patrol/voice_ref_files /voice_ref_files

RUN mkdir /xml
RUN mkdir /output

COPY xml/basic_server.xml /xml
COPY entry.sh /
ENTRYPOINT ["/entry.sh"]
