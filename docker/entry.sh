#!/bin/bash

RESULT_FILE=${RESULT_FILE-"result.json"}
PORT=${PORT="5060"}

if [ -z "${XML_CONF}" ]; then
    for SCENARIO in /xml/*.xml; do
        echo "------ Running ${SCENARIO} -------"

        /git/voip_patrol/voip_patrol --port ${PORT} --conf ${SCENARIO} --output /output/${RESULT_FILE}

        echo "---- Done running ${SCENARIO} ----"
    done
else
    echo "Running 1 scenario: ${XML_CONF}"
    /git/voip_patrol/voip_patrol --port ${PORT} --conf /xml/${XML_CONF} --output /output/${RESULT_FILE}
fi

chmod 777 /output
chmod 666 /output/${RESULT_FILE}
