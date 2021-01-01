import json


class Response:
    @staticmethod
    def json(code, msg, username=None):
        response = {
            "statusCode": code,
            "statusMessage": msg
        }
        if username is not None:
            response["username"] = username

        return json.dumps(response)

    @staticmethod
    def success(username):
        return Response.json("2000", "success", username)

    @staticmethod
    def formatError(msg):
        return Response.json("4001", "Format Error (" + msg + ")")

    @staticmethod
    def invalidValueError(msg):
        return Response.json("4002", "Invalid Value Error (" + msg + ")")

    @staticmethod
    def unsupportedError(msg):
        return Response.json("4003", "Unsupported Error (" + msg + ")")
