const https = require('https');
const crypto = require('crypto');

module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');

    try {
        const noname_type = req.query.type || (req.body && req.body.type);
        context.log('noname_type:', noname_type);

        let requestBody = req.body;
        if (Buffer.isBuffer(req.body)) {
            // If the body is a buffer, convert it to a string
            requestBody = req.body.toString('utf-8');
        }

        let payload;
        if (typeof requestBody === 'string') {
            try {
                payload = JSON.parse(requestBody); // Parse the string into JSON
            } catch (parseError) {
                context.log('Error parsing JSON:', parseError);
                throw new Error('Invalid JSON format');
            }
        } else {
            // If requestBody is already an object
            payload = requestBody;
        }

        context.log("Received request body:", payload);

        if (payload) {
            await sendDataToSentinel(payload, context, noname_type);
            context.res = { body: 'Data sent to Sentinel successfully.' };
        } else {
            context.res = { status: 400, body: 'No payload received.' };
        }
    } catch (error) {
        context.log(error);
        context.res = {
            status: 500,
            body: `Error processing request: ${error.message}`
        };
    }
};

async function sendDataToSentinel(data, context, noname_type) {
    const workspaceId = process.env['WorkspaceId'];
    const sharedKey = process.env['SharedKey'];
    const apiVersion = '2016-04-01';
    const processingDate = new Date().toUTCString();
    const body = JSON.stringify(data);
    const contentLength = Buffer.byteLength(body, 'utf8');

    const signature = buildSignature(workspaceId, sharedKey, 'POST', contentLength, 'application/json', processingDate);
    const url = `https://${workspaceId}.ods.opinsights.azure.com/api/logs?api-version=${apiVersion}`;

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': signature,
            'Log-Type': `Noname_${noname_type}`,
            'x-ms-date': processingDate,
            'time-generated-field': ''
        }
    };

    const req = https.request(url, options, (res) => {
        context.log(`Data sent to Sentinel. Response status: ${res.statusCode}`);
        res.on('data', (d) => {
            process.stdout.write(d);
        });
    });

    req.on('error', (error) => {
        context.log.error(`Error sending data to Sentinel: ${error.message}`);
        throw error;
    });

    req.write(body);
    req.end();
}

function buildSignature(workspaceId, sharedKey, method, contentLength, contentType, date) {
    const stringToSign = method + '\n' + contentLength + '\n' + contentType + '\n' + 'x-ms-date:' + date + '\n' + '/api/logs';
    const decodedKey = Buffer.from(sharedKey, 'base64');
    const hmac = crypto.createHmac('sha256', decodedKey);
    hmac.update(stringToSign);
    const signature = hmac.digest('base64');
    return 'SharedKey ' + workspaceId + ':' + signature;
}
