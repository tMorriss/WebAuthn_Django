function assertion_options(options) {
    return $.post({
        url: "/assertion/options",
        data: JSON.stringify(options),
        contentType: 'application/json'
    })
}

function assertion_result(rawCredential) {
    credential = {
        id: rawCredential.id,
        response: {
            authenticatorData: bufferToBase64Url(rawCredential.response.authenticatorData),
            clientDataJSON: bufferToBase64Url(rawCredential.response.clientDataJSON),
            signature: bufferToBase64Url(rawCredential.response.signature),
            userHandle: bufferToString(rawCredential.response.userHandle)
        }
    }
    if ($('#remote_challenge').length) {
        credential.remote_challenge = $("#remote_challenge").val()
    }
    return $.post({
        url: "/assertion/result",
        data: JSON.stringify(credential),
        contentType: 'application/json'
    })
}

function attestation_options(options) {
    return $.post({
        url: "/attestation/options",
        data: JSON.stringify(options),
        contentType: 'application/json'
    })
}

function attestation_result(rawCredential) {
    credential = {
        id: rawCredential.id,
        response: {
            attestationObject: bufferToBase64Url(rawCredential.response.attestationObject),
            clientDataJSON: bufferToBase64Url(rawCredential.response.clientDataJSON),
        },
        type: rawCredential.type
    }
    try {
        credential.response.transports = rawCredential.response.getTransports();
        if (credential.response.transports.length == 0) {
            credential.response.transports = ['internal'];
        }
    } catch (TypeError) {
        credential.response.transports = ['internal'];
    }
    return $.post({
        url: "/attestation/result",
        data: JSON.stringify(credential),
        contentType: 'application/json'
    })
}

function getList(username) {
    return $.get(list_url, { username: username });
}

function deleteKey(pk) {
    $.post({
        url: delete_url,
        data: JSON.stringify({ pk: pk }),
        contentType: 'application/json'
    }).done(() => {
        $("#key-" + pk).remove();
    });
}
