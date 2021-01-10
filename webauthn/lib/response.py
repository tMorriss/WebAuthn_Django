import json


class Response:
    @staticmethod
    def json(code, msg, data=None):
        response = {
            "statusCode": code,
            "statusMessage": msg
        }
        if data is not None:
            response.update(data)

        return json.dumps(response)

    @staticmethod
    def success(data):
        return Response.json("2000", "success", data)

    @staticmethod
    def formatError(msg):
        return Response.json("4001", "Format Error (" + msg + ")")

    @staticmethod
    def invalidValueError(msg):
        return Response.json("4002", "Invalid Value Error (" + msg + ")")

    @staticmethod
    def unsupportedError(msg):
        return Response.json("4003", "Unsupported Error (" + msg + ")")
