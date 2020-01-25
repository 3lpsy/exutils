import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace, _SubParsersAction

BOOFUZZ_AVAILABLE = False
try:
    from boofuzz import (
        Session,
        Target,
        SocketConnection,
        s_initialize,
        s_string,
        s_delim,
        s_get,
        pedrpc,
    )

    BOOFUZZ_AVAILABLE = True
except ImportError as e:
    pass

# for Vulnserver
# ./exutils.py boofuzz -t 172.28.128.21 -p 9999 -k 'i:TRUN' -k 's:TRUN,0' -k 'd: ,0' -k 's:FUZZ,1' -c 'TRUN' --procmon-auto --procmon-startcmds 'C:/Users/pawn/Desktop/Vulnserver/vulnserver.exe'


def run(args: List[Any]):
    if not BOOFUZZ_AVAILABLE:
        print("boofuzz is not installed. please install it to use boofuzz sub command")
        sys.exit()
    connection = SocketConnection(args["target"], args["port"], proto=args["proto"])
    targs = {"connection": connection}
    procmon_target = False
    procmon_port = False
    if "procmon_auto" in args:
        procmon_target = args["target"]
        procmon_port = 26002
    elif "procmon_target" in args and args["procmon_target"]:
        procmon_target = args["procmon_target"]
        procmon_port = args["procmon_port"] if "procmon_port" in args else 26002
    if procmon_target and procmon_port:
        print(f"Attaching process monitor connection: {procmon_target}, {procmon_port}")
        targs["procmon"] = pedrpc.Client(procmon_target, procmon_port)
    if "procmon_startcmds" in args and args["procmon_startcmds"]:
        print("Setting Start commands", args["procmon_startcmds"])
        targs["procmon_options"] = {"start_commands": args["procmon_startcmds"]}
    target = Target(**targs)
    sargs = {"target": target}
    # sargs['crash_threshold_element'] = 100
    session = Session(**sargs)
    for fk in args["fuzz_key"]:
        action = fk.split(":", 1)[0]
        fargs = fk.split(":", 1)[1]
        fargssplit = fargs.split(",", 1)
        firstarg = fargssplit[0]
        secarg = None
        if len(fargssplit) > 1:
            secarg = fargssplit[1]
        if action == "i":
            print(f"s_initialize('{firstarg}')")
            s_initialize(firstarg)
        elif action == "s":
            fuzzable = secarg == "1" if secarg else False
            print(f"s_string('{firstarg}',fuzzable={fuzzable})")
            s_string(firstarg, fuzzable=fuzzable)
        elif action == "d":
            fuzzable = secarg == "1" if secarg else False
            print(f"s_delim('{firstarg}',fuzzable={fuzzable})")
            s_delim(firstarg, fuzzable=fuzzable)
    for ck in args["connect_key"]:
        print(f"session.connect(s_get('{ck}'))")
        session.connect(s_get(ck))
    session.fuzz()


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser(
        "boofuzz",
        help="boofuzz (highly experimental, typically needs to be customized)",
    )
    parser.add_argument(
        "-t", "--target", type=str, help="target ip/host", required=True
    )

    parser.add_argument("-p", "--port", type=int, help="target port", required=True)
    parser.add_argument(
        "--proto", type=str, help="target proto", choices=["tcp", "udp"], default="tcp",
    )
    parser.add_argument(
        "-k",
        "--fuzz-key",
        action="append",
        help="inject keystr (-k 'i:TRUN' -k 's:TRUN,0' -k 'd: ,0' -k 's:FUZZ')",
        required=True,
    )
    parser.add_argument(
        "-c",
        "--connect-key",
        action="append",
        help="connect keyst (-c 'TRUN')",
        required=True,
    )
    parser.add_argument(
        "--procmon-auto", action="store_true", help="target is running process monitor"
    )
    parser.add_argument("--procmon-target", type=str, help="procmon target ip/host")
    parser.add_argument("--procmon-port", type=int, help="procmon port", default=26002)
    parser.add_argument(
        "--procmon-startcmds", type=str, action="append", help="procmon start comand"
    )
    return parser


def normalize(args: Namespace) -> dict:
    return vars(args)

