from setuptools import setup, find_packages

version = '3.4.0'

setup(
    name='tacacs_plus',
    version=version,
    description="A client for TACACS+ authentication",
    long_description=None,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Programming Language :: Python :: 3.15',
    ],
    keywords='tacacs tacacs+ tacacs_plus auth authentication pap chap tls',
    author='Ryan Petrello',
    author_email='ryan@ryanpetrello.com',
    maintainer='durd',
    maintainer_email='brodin@durd.net',
    url='https://github.com/durd/tacacs_plus',
    project_urls={
        'Documentation': 'https://durd.github.io/tacacs_plus/',
        'Source': 'https://github.com/durd/tacacs_plus',
    },
    license='BSD',
    packages=find_packages(exclude=['examples', 'tests', 'tests.*']),
    python_requires='>=3.10',
    tests_require=['pytest', 'pytest-cov'],
    include_package_data=True,
    scripts=['bin/tacacs_client'],
    zip_safe=False
)
