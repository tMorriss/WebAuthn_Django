let successCode = '2000';
const conditionalUiController = new AbortController();

function register(requireResidentKey) {
    $('#resultMsg').text("");
    // if (!isUVPAA) {
    //     $('#resultMsg').text("isUVPAA is false");
    //     return;
    // }
    var options = {
        "username": $("#register_username").val(),
        "requireResidentKey": requireResidentKey,
    }
    conditionalUiController.abort('AnotherSessionRequested'); //前の処理をキャンセル
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
    // if (!isUVPAA) {
    //     $('#resultMsg').text("isUVPAA is false");
    //     return;
    // }
    var options = {}
    if ($("#register_username").val() != "") {
        options["username"] = $("#register_username").val()
    }
    conditionalUiController.abort('AnotherSessionRequested'); //前の処理をキャンセル
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

        // 生体認証
        return navigator.credentials.get({ publicKey: options });
    }).then((credential) => {
        // resultリクエスト
        return assertion_result(credential);
    }).then((response) => {
        $('#resultMsg').text(response);
    }).catch(e => {
        $('#resultMsg').text(e);
    });
}

function fireConditionalUi() {
    $('#resultMsg').text("");
    if (!isUVPAA) {
        $('#resultMsg').text("isUVPAA is false");
        return;
    }
    // optionsリクエスト
    assertion_options({}).then((response) => {
        // レスポンスをデコード
        options = JSON.parse(response);
        if (options.statusCode != successCode) {
            $('#resultMsg').text(response);
            return;
        }
        options.challenge = new TextEncoder().encode(options.challenge);
        // ConditionalUI実行
        return navigator.credentials.get({
            mediation: 'conditional',
            publicKey: options,
            signal: conditionalUiController.signal
        });

    }).then((credential) => {
        // resultリクエスト
        return assertion_result(credential);
    }).then((response) => {
        $('#resultMsg').text(response);
    }).catch(e => {
        if (e !== 'AnotherSessionRequested') {
            $('#resultMsg').text(e);
        }
    });
}
