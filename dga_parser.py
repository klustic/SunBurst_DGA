import argparse

from lib.message import TimestampMessage, ServiceStatusMessage, HostnameMessage


def route_domain(domain: str):
    try:
        return TimestampMessage(domain)
    except ValueError:
        pass

    try:
        return ServiceStatusMessage(domain)
    except ValueError:
        pass

    try:
        return HostnameMessage(domain)
    except ValueError:
        pass

    raise Exception('Unknown message type')


def main():
    messages_by_userid = {}

    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='A file containing hostnames created using this DGA')
    args = parser.parse_args()

    with open(args.file) as f:
        domains = f.read().strip().split()

    for domain in domains:
        message = route_domain(domain)
        if message.user_id not in messages_by_userid:
            messages_by_userid[message.user_id] = []
        messages_by_userid[message.user_id].append(message)

    for user_id in messages_by_userid:
        print('\n' + user_id)
        print('\t' + '\n\t'.join(str(m) for m in messages_by_userid[user_id]))


if __name__ == '__main__':
    main()
