import timeit
from sys import version_info as pyver

from django import VERSION as djver
from django.conf import settings
from django.contrib.auth.hashers import make_password


def test():
    make_password('lètmein', hasher='pbkdf2_sha256')


if __name__ == '__main__':
    settings.configure()
    hash_100_times = timeit.timeit(stmt='test()', 
                                   setup='from __main__ import test', 
                                   number=100)
    hash_average = int(hash_100_times * 10)
    python_version = '.'.join(map(str, pyver[:3]))
    django_version = '.'.join(map(str, djver[:3]))
    version_info = f'(Python {python_version}, Django {django_version})'
    print(f'Hashing time: {hash_average}ms {version_info}.')
