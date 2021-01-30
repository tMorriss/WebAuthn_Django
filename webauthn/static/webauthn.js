let successCode = '2000';

function base64UrlToBuffer(base64) {
    let binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/') + "=".repeat(4 - base64.length % 4));
    let len = binary.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bufferToBase64Url(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function bufferToString(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}

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

async function registerWithUVPAA() {
    $('#resultMsg').text("");
    // FIDO対応か確認
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(
    ).then((result) => {
        if (result) {
            register();
        } else {
            $('#resultMsg').text("isUVPAA is false");
        }
    });
}

function register() {
    $('#resultMsg').text("");
    var options = {
        "username": $("#register_username").val(),
    }
    // optionsリクエスト
    attestation_options(options).then((response) => {
        // レスポンスをデコード
        options = JSON.parse(response);
        if (options.statusCode != successCode) {
            $('#resultMsg').text(response);
            return
        }
        options.user.id = new TextEncoder().encode(options.user.id);
        options.challenge = new TextEncoder().encode(options.challenge);
        for (let i = 0; i < options.excludeCredentials.length; i++) {
            options.excludeCredentials[i].id = base64UrlToBuffer(options.excludeCredentials[i].id)
        }
        // 鍵生成
        return navigator.credentials.create({ publicKey: options });
    }).then((credential) => {
        // resultリクエスト
        return attestation_result(credential);
    }).catch(e => {
        if (e.name == "InvalidStateError" && e.message == "The user attempted to register an authenticator that contains one of the credentials already registered with the relying party.") {
            $('#resultMsg').text("二重登録エラー");
            return;
        } else {
            $('#resultMsg').text(e);
        }
    }).then((response) => {
        $('#resultMsg').text(response);
    });
}

function authWithUVPAA() {
    $('#resultMsg').text("");
    // FIDO対応か確認
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(
    ).then((result) => {
        if (result) {
            auth();
        } else {
            $('#resultMsg').text("isUVPAA is false");
        }
    });
}

function showList() {
    username = $("#register_username").val();
    getList(username).done((response) => {
        responseJson = JSON.parse(response);
        if (responseJson.statusCode != successCode) {
            return;
        }

        tblText = "<table><tr><th>削除</th><th>fmt</th><th>登録日</th><th>credentialId</th></tr>";
        for (let i = 0; i < responseJson.keys.length; i++) {
            tblText += "<tr id='key-" + responseJson.keys[i].pk + "'><td><button onclick='deleteKey(" + responseJson.keys[i].pk + ")'>削除</button></td>";
            tblText += "<td>" + responseJson.keys[i].fmt + "</td><td>" + responseJson.keys[i].regTime + "</td><td>" + responseJson.keys[i].credentialId + "</td>";
        }
        tblText += "</table>";
        $("#tblList").text("");
        $("#tblList").append(tblText);
    });
}

function generateQR() {
    username = $("#register_username").val();
    $.post({
        url: qr_generate_url,
        data: JSON.stringify({ username: username }),
        contentType: 'application/json'
    }).done((response) => {
        responseJson = JSON.parse(response);
        if (responseJson.statusCode != successCode) {
            $('#resultMsg').text("failed: status=" + responseJson.statusMessage);
            return;
        }
        $('#qrcode').text("");
        $('#qrcode').qrcode({
            width: 200,
            height: 200,
            correctLevel: 1,
            text: responseJson.url
        });
        $('#verify_link').text("");
        $('#verify_link').append('<a href="' + responseJson.url + '">' + responseJson.url + '</a>');

        // ポーリング
        var timer = setInterval(function (challenge) {
            $.get(
                qr_check_url,
                { challenge: challenge }
            ).done((response) => {
                responseJson = JSON.parse(response);
                if (responseJson.statusCode != successCode) {
                    $('#resultMsg').text("failed: status=" + responseJson.statusMessage);
                    clearInterval(timer);
                }
                // 成功だったらログイン
                if (responseJson.verified) {
                    $('#resultMsg').text("Logged in");
                    clearInterval(timer);
                }
            }).fail(() => {
                clearInterval(timer);
            });
        }, 1000, responseJson.challenge);
    }).fail((response) => {
        console.log(response);
    });
}
function auth() {
    $('#resultMsg').text("");
    var options = {}
    if ($("#register_username").val() != "") {
        options["username"] = $("#register_username").val()
    }
    // optionsリクエスト
    assertion_options(options).then((response) => {
        // レスポンスをデコード
        options = JSON.parse(response);
        if (options.statusCode != successCode) {
            $('#resultMsg').text(response);
            return;
        }
        options.challenge = new TextEncoder().encode(options.challenge);
        for (let i = 0; i < options.allowCredentials.length; i++) {
            options.allowCredentials[i].id = base64UrlToBuffer(options.allowCredentials[i].id);
        }

        // 鍵生成
        return navigator.credentials.get({ publicKey: options });
    }).then((credential) => {
        // resultリクエスト
        return assertion_result(credential);
    }).catch(e => {
        $('#resultMsg').text(e);
        return;
    }).then((response) => {
        $('#resultMsg').text(response);
    });
}
