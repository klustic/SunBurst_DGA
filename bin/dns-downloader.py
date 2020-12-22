import argparse

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', default='avsvmcloud.com', help='Base domain to query')
    parser.add_argument('--api-key', required=True, help='Security Trails API key')
    args = parser.parse_args()

    url = f'https://api.securitytrails.com/v1/domain/{args.domain}/subdomains'
    headers = {
        'Accept': 'application/json',
        'APIKEY': args.api_key
    }
    querystring = {
        'children_only': 'false'
    }

    r = requests.get(url, headers=headers, params=querystring)
    print(r.json())


if __name__ == '__main__':
    main()
