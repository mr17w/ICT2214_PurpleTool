def _pyi_rthook():
    import sys
    import multiprocessing
    import multiprocessing.spawn
    from subprocess import _args_from_interpreter_flags
    multiprocessing.process.ORIGINAL_DIR = None

    def _freeze_support():
        if len(sys.argv) >= 2 and sys.argv[-2] == '-c' and sys.argv[-1].startswith(('from multiprocessing.resource_tracker import main', 'from multiprocessing.forkserver import main')):
            if set(sys.argv[1:-2]) == set(_args_from_interpreter_flags()):
                exec(sys.argv[-1])
                sys.exit()
        if multiprocessing.spawn.is_forking(sys.argv):
            kwds = {}
            for arg in sys.argv[2:]:
                name, value = arg.split('=')
                if value == 'None':
                    kwds[name] = None
                else:
                    kwds[name] = int(value)
            multiprocessing.spawn.spawn_main(**kwds)
            sys.exit()
    multiprocessing.freeze_support = multiprocessing.spawn.freeze_support = _freeze_support
_pyi_rthook()
del _pyi_rthook