from __future__ import print_function

import sibyl.testlauncher
import sibyl.abi
import sibyl.abi.arm
import sibyl.abi.x86
import sibyl.abi.mips
import sibyl.config
from binaryninja import *
import functools
import miasm2.analysis.machine


# Map calling convention [Binja arch][Binja cc name] -> sibyl cc
CC_MAP = {
    'armv7': {
        'cdecl': sibyl.abi.arm.ABI_ARM,
    },
    'armv7eb': {
        'cdecl': sibyl.abi.arm.ABI_ARM,
    },
    'mips32': {
        'o32': sibyl.abi.mips.ABI_MIPS_O32,
    },
    'mipsel32': {
        'o32': sibyl.abi.mips.ABI_MIPS_O32,
    },
    'thumb2': {
        'cdecl': sibyl.abi.arm.ABI_ARM,
    },
    'thumb2eb': {
        'cdecl': sibyl.abi.arm.ABI_ARM,
    },
    'x86': {
        'cdecl': sibyl.abi.x86.ABIStdCall_x86_32,
        'fastcall': sibyl.abi.x86.ABIFastCall_x86_32,
        'stdcall': sibyl.abi.x86.ABIStdCall_x86_32,
    },
    'x86_64': {
        'sysv': sibyl.abi.x86.ABI_AMD64_SYSTEMV,
        'win64': sibyl.abi.x86.ABI_AMD64_MS,
    },
}

# Arch mapping [Binja arch] -> Miasm arch
ARCH_MAP = {
    'aarch64': 'aarch64l',  # TODO: Why doesn't binja have aarch64b and aarch64l?
    'armv7': 'arml',
    'armv7eb': 'armb',
    'thumb2': 'armtl',
    'thumb2eb': 'armtb',
    'mipsel32': 'mips32l',
    'mips32': 'mips32b',
    'x86': 'x86_32',
    'x86_64': 'x86_64',
}


class AnalysisThread(BackgroundTaskThread):
    """
    Sibyl's IDA plugin uses subprocesses in order to fully exploit multiprocessing.
    That feels a bit hacky to me so I'm going with a simple background thread...
    This ways it's way slower though.
    """

    def __init__(self, tests, filename, base_addr, arch, funk_addrs, funk_ccs, callback, timeout=1):
        super(AnalysisThread, self).__init__('Running Sibyl...', True)

        self._tests = tests
        self._filename = filename
        self._arch = arch
        self._base_addr = base_addr
        self._funk_addrs = funk_addrs
        self._funk_ccs = funk_ccs
        self._callback = callback
        self._timeout = timeout

    def run(self):
        for addr, cc in zip(self._funk_addrs, self._funk_ccs):
            # This could be cached based on cc...
            tl = sibyl.testlauncher.TestLauncher(
                filename=self._filename,
                machine=miasm2.analysis.machine.Machine(self._arch),
                abicls=cc,
                tests_cls=self._tests,
                engine_name=sibyl.config.config.jit_engine,
                map_addr=self._base_addr
            )
            possible_names = tl.run(addr, timeout_seconds=self._timeout)
            if len(possible_names) > 0:
                self._callback(addr, possible_names)

        self.finish()


def rename_function(bv, addr, names, prefix='', comment=True):
    print('sibyl> 0x{:08X}: [{}]'.format(addr, ', '.join(names)))
    funk = bv.get_function_at(addr)
    funk.name = prefix + names[0]
    if comment:
        funk.set_comment(addr, 'Sibyl: {}'.format(', '.join(names)))


def guess(bv, funks, tests, prefix='s_', add_comment=True, timeout=1):
    cc_map = CC_MAP[bv.arch.name]
    m_arch = ARCH_MAP[bv.arch.name]

    funks = filter(lambda x: x.calling_convention.name in cc_map, funks)

    addrs = [f.start for f in funks]
    ccs = [cc_map[f.calling_convention.name] for f in funks]

    callback = functools.partial(rename_function, bv, prefix=prefix, comment=add_comment)

    # Create and start the analysis thread
    analysis = AnalysisThread(
        tests,
        bv.file.filename,
        bv.start,
        m_arch,
        addrs,
        ccs,
        callback,
        timeout=timeout
    )
    analysis.run()


def cmd_run(bv):
    test_groups = sibyl.config.config.available_tests.keys()

    gui_label_options = LabelField('Options')
    gui_tests = ChoiceField('Tests:', test_groups)
    gui_prefix = TextLineField('Function prefix:')
    gui_selector = ChoiceField('Function selector:', ('sub_.*', '.*'))
    gui_comment = ChoiceField('Add comment:', ('Yes', 'No'))

    ret = get_form_input(
        (gui_label_options, gui_tests, gui_prefix, gui_selector, gui_comment),
        'Sibyl'
    )

    # User canceled
    if not ret:
        return

    # Sanitize options
    tests = sibyl.config.config.available_tests[test_groups[gui_tests.result]]
    rename_only_unknowns = gui_selector.choices[gui_selector.result] == 'sub_.*'
    add_comment = gui_comment.choices[gui_comment.result] == 'Yes'
    prefix = gui_prefix.result.strip()

    # Filter
    funks = bv.functions
    if rename_only_unknowns:
        funks = filter(lambda x: x.name.startswith('sub_'), funks)

    # Do the magic
    guess(bv, funks, tests, prefix=prefix, add_comment=add_comment, timeout=1)


def cmd_run_on_function(bv, funk):
    guess(bv, [funk], prefix='', add_comment=False, timeout=5)


PluginCommand.register(
    name='Run Sybil on whole file',
    description='Infer functions\' names from side effects',
    action=cmd_run
)

PluginCommand.register_for_function(
    name='Run Sybil on current function',
    description='Infer function\'s name from its side effects',
    action=cmd_run_on_function
)
