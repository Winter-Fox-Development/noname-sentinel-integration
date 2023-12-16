const { app } = require('@azure/functions');
const axios = require('axios');
const crypto = require('crypto');
const moment = require('moment');



app.http('noname-webhook-post', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (req, context) => {
        try {
            const noname_type = await req.query.get('type');
            context.log(noname_type)
            const requestBody = await readStream(req.body);
            context.log("Received request body:", requestBody);

            if (requestBody) {
                const payload = JSON.parse(requestBody);  // Parse the string into JSON
                await sendDataToSentinel(payload, context, noname_type);
                context.res = { body: 'Data sent to Sentinel successfully.' };
            } else {
                context.res = { status: 400, body: 'No payload received.' };
            }
        } catch (error) {
            context.log(error)
            context.res = {
                status: 500,
                body: `Error processing request: ${error.message}`
            };
        }
    }
});

async function readStream(readableStream) {
    let chunks = [];
    for await (const chunk of readableStream) {
        chunks.push(Buffer.from(chunk));
    }
    let buffer = Buffer.concat(chunks);
    let stringData = buffer.toString('utf8');
    return stringData;
}

async function sendDataToSentinel(data, context, noname_type) {
    const workspaceId = process.env['WorkspaceId'];
    const sharedKey = process.env['SharedKey'];
    const apiVersion = '2016-04-01';
    const processingDate = moment.utc().format('ddd, DD MMM YYYY HH:mm:ss') + ' GMT';
    const body = JSON.stringify(data);
    const contentLength = Buffer.byteLength(body, 'utf8');

    const signature = buildSignature(workspaceId, sharedKey, 'POST', contentLength, 'application/json', processingDate);
    const url = `https://${workspaceId}.ods.opinsights.azure.com/api/logs?api-version=${apiVersion}`;

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': `Noname_${noname_type}`,
        'x-ms-date': processingDate,
        'time-generated-field': ''
    };

    try {
        const response = await axios.post(url, body, { headers: headers });
        context.log(`Data sent to Sentinel. Response status: ${response.status}`);
    } catch (error) {
        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            context.log.error(`Error sending data to Sentinel: ${error.response.status}, ${error.response.data}`);
        } else if (error.request) {
            // The request was made but no response was received
            context.log.error(`Error sending data to Sentinel: No response received.`);
        } else {
            // Something happened in setting up the request that triggered an Error
            context.log.error(`Error sending data to Sentinel: ${error.message}`);
        }
        throw error;
    }

}

function buildSignature(workspaceId, sharedKey, method, contentLength, contentType, date) {
    const stringToSign = method + '\n' + contentLength + '\n' + contentType + '\n' + 'x-ms-date:' + date + '\n' + '/api/logs';
    const decodedKey = Buffer.from(sharedKey, 'base64');
    const hmac = crypto.createHmac('sha256', decodedKey);
    hmac.update(stringToSign);
    const signature = hmac.digest('base64');
    return 'SharedKey ' + workspaceId + ':' + signature;
}
