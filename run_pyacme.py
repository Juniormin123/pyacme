"""
run the script with `sudo`
"""


if __name__ == '__main__':
    from pyacme.util import main_param_parser
    from pyacme.execution import main_add_args, main
    args = main_add_args()

    # test
    print(args)

    param_dict = main_param_parser(args)
    # test
    print(param_dict)

    main(**param_dict)
