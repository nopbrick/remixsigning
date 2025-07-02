import * as crypto from "crypto"

function verifyRemixCookie(cookieValue: string, secret) {
    // Split the cookie value and signature
    const fullCookie = cookieValue.replace("__session=", ""); // Remove "__session="
    const parts = fullCookie.split('.');

    if (parts.length !== 2) {
        console.log("No signature found");
        return null;
    }

    const [base64Data, urlEncodedSignature] = parts;

    const signature = decodeURIComponent(urlEncodedSignature);

    // Remix uses HMAC-SHA256
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(base64Data);
    const expectedSignature = hmac.digest('base64');

    if (signature === expectedSignature) {
        const decoded = Buffer.from(base64Data, 'base64').toString('utf-8');
        console.log(JSON.stringify(decoded));
        return JSON.parse(decoded);
    } else {
        console.log("Signature verification failed");
        console.log("Expected:", expectedSignature);
        console.log("Actual:", signature);
        return null;
    }
}

function signRemixCookie(data, secret) {
    const jsonString = JSON.stringify(data);

    const base64Data = Buffer.from(jsonString).toString('base64');

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(base64Data);
    const signature = hmac.digest('base64');

    // URL encode the signature
    const urlEncodedSignature = encodeURIComponent(signature);
    const fullCookieValue = `__session=${base64Data}.${urlEncodedSignature}`;

    return fullCookieValue;
}

console.log("=== Verifying original cookie ===");
const result = verifyRemixCookie(
    "__session=eyJ1c2VyTmFtZSI6IlRlc3Qg...", //PUT COOKIE HERE
    "s3cret1"
);

if (result) {
    console.log("Original cookie data:", result);

    // Modify the decoded data
    console.log("\n=== Creating modified cookie ===");
    const modifiedData = {
        ...result,
        userName: "Modified Admin",
        subscriptionId: "LucianoTest",
        customField: "I added this!" // Add a new field
    };

    console.log("Modified data:", modifiedData);

    // Sign the modified data to create a new valid cookie
    const newCookie = signRemixCookie(modifiedData, "s3cret1");
    console.log("\nNew signed cookie:");
    console.log(newCookie);

    // Verify the new cookie works
    console.log("\n=== Verifying new cookie ===");
    const verifiedModified = verifyRemixCookie(newCookie, "s3cret1");
    console.log("Verified modified data:", verifiedModified);
}
