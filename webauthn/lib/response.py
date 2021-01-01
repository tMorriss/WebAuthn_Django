import json


class Response:
    @staticmethod
    def json(code, msg):
        return json.dumps({
            "statusCode": code,
            "statusMessage": msg
        })

    @staticmethod
    def success():
        return Response.json("2000", "success")

    @staticmethod
    def formatError(msg):
        return Response.json("4001", "Format Error (" + msg + ")")

    @staticmethod
    def invalidValueError(msg):
        return Response.json("4002", "Invalid Value Error (" + msg + ")")

    @staticmethod
    def unsupportedError(msg):
        return Response.json("4003", "Unsupported Error (" + msg + ")")
