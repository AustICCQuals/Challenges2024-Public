import yaml, os, sys, string, logging, copy
from colorlog import ColoredFormatter
from ctfcli.core.challenge import Challenge

LOG_FORMAT = '%(log_color)s%(message)s%(reset)s'
sh = logging.StreamHandler()
sh.setFormatter(ColoredFormatter(LOG_FORMAT))
log = logging.getLogger('ctfcli-wrapper')
log.setLevel(logging.INFO)
log.addHandler(sh)

def process_chall(chall_data, global_config):
    processed = chall_data.copy()

    category = chall_data['category']
    chall_id = chall_data['id']

    df = global_config['global_defaults']
    for k in df:
        if k not in processed:
            processed[k] = df[k]
        elif type(processed[k]) == dict:
            processed[k] = df[k] | processed[k]

    # run with --visible to set to visible (default is hidden)
    if '--visible' in sys.argv:
        processed['state'] = 'visible'

    return processed


def format_chall(chall_data):
    return f'{chall_data["category"]}/{chall_data["id"]}'


def main():
    if len(sys.argv) < 4:
        print(f'usage: {sys.argv[0]} (install|install-with-skip|sync) CHALL_DIR GLOBAL_CONFIG_FILE')
        exit(1)

    cmd = sys.argv[1]

    if cmd not in ['install', 'install-with-skip', 'sync']:
        print(f'usage: {sys.argv[0]} (install|install-with-skip|sync) CHALL_DIR GLOBAL_CONFIG_FILE')
        exit(1)

    # directory containing subdirectories (or more) which eventually
    # contain ctfcli.yaml files to install
    challs_dir = sys.argv[2]
    global_config_file = sys.argv[3]

    # make sure there are no challenge conflicts if installing
    exists = []
    if cmd in ['install', 'install-with-skip', 'sync']:
        existing_challs = Challenge.load_installed_challenges()
        for dir_name, _, files in os.walk(challs_dir):
            if 'ctfcli.yaml' in files:
                f = os.path.join(dir_name, 'ctfcli.yaml')
                chall_data = yaml.safe_load(open(f, 'r'))
                if any(chall_data['name'] == c['name'] for c in existing_challs):
                    if cmd == 'install':
                        log.critical(f'{format_chall(chall_data)} already exists. Use sync to update challenges instead or install-with-skip to install challenges but skip existing ones.')
                        exit(1)
                    if cmd in ['install-with-skip', 'sync']:
                        exists.append(chall_data['name'])

    global_config = yaml.safe_load(open(global_config_file, 'r'))

    NUM_CHALLS = 0
    HEALTH_BAD = 0

    # traverse the given directory untill we find ctfcli.yaml files
    for dir_name, _, files in os.walk(challs_dir):
        if 'ctfcli.yaml' in files:
            f = os.path.join(dir_name, 'ctfcli.yaml')
            log.info(f'Loading file: {f}')
            chall_data = yaml.safe_load(open(f, 'r'))

            if cmd == 'install-with-skip' and chall_data['name'] in exists:
                log.critical(f'\tAlready exists, skipping...\n')
                continue
            processed = process_chall(chall_data, global_config)
            if cmd == 'install' or cmd == 'install-with-skip':
                log.info(f'Installing: {format_chall(processed)}')
                chall = Challenge(f, overrides=processed)
                chall.create()
                log.info(f'Successfully installed: {format_chall(processed)}')
            elif cmd == 'sync':
                if chall_data['name'] not in exists:
                    log.critical(f'\tDoesn\'t exist, skipping...\n')
                    continue
                Challenge(f, overrides=processed).sync()
                chall = Challenge(f, overrides=processed)
                chall.sync()
                log.info(f'Successfully synced: {format_chall(processed)}')

            NUM_CHALLS += 1
            print()


    c = { 'install': 'Installed', 'install-with-skip': 'Installed(with skip)', 'sync': 'Updated' }[cmd]
    log.info(f'{c} {NUM_CHALLS} challenges')


if __name__ == '__main__':
    main()
