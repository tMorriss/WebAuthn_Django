import json


class Response:
    @staticmethod
    def json(code, msg, username):
        return json.dumps({
            "statusCode": code,
            "statusMessage": msg,
            "username": username
        })

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
