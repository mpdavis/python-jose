import base64


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def timedelta_total_seconds(delta):
    try:
        delta.total_seconds
    except AttributeError:
        # On Python 2.6, timedelta instances do not have
        # a .total_seconds() method.
        total_seconds = delta.days * 24 * 60 * 60 + delta.seconds
    else:
        total_seconds = delta.total_seconds()

    return total_seconds
