
def CREATE_ORDER(*, waiter_id: int, table_id: int, order: list):
    request_dict = {
        "body": {
            "cmd": "CREATE",
            "waiter_id": waiter_id,
            "table_id": table_id,
            "order": order
        }
    }

    return request_dict

def CANCEL_ORDER(*, waiter_id: int, table_id: int):
    request_dict = {
        "body": {
            "cmd": "CANCEL",
            "waiter_id": waiter_id,
            "table_id": table_id,
        }
    }

    return request_dict


def ORDER_READY(*, waiter_id: int, table_id: int):
    request_dict = {
        "body": {
            "cmd": "READY",
            "waiter_id": waiter_id,
            "table_id": table_id,
        }
    }

    return request_dict

def GOOD_REQUEST():
    request_dict = {
        "body": {
            "status": "200"
        }
    }

    return request_dict

def BAD_REQUEST():
    request_dict = {
        "body": {
            "status": "400",
        }
    }

    return request_dict

