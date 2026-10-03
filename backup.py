import argparse
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

def main():
    parser=argparse.ArgumentParser(description='Back up source and optionally run results; dataset excluded.')
    parser.add_argument('--output',required=True)
    parser.add_argument('--include-runs',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parent
    output=Path(args.output).resolve()
    output.parent.mkdir(parents=True,exist_ok=True)
    excluded={'.venv','venv','__pycache__','.git','data','build','dist'}
    if not args.include_runs:excluded.add('runs')
    count=0
    with ZipFile(output,'x',compression=ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob('*')):
            relative=path.relative_to(root)
            if not path.is_file() or path.is_symlink() or path.resolve()==output:continue
            if any(part in excluded for part in relative.parts):continue
            if path.suffix in ('.zip','.pcap','.pcapng','.pyc') or path.name=='.env':continue
            archive.write(path,root.name+'/'+relative.as_posix());count+=1
    print(f'Backup saved: {output} ({count} files). Dataset and virtual environment excluded.')

if __name__=='__main__':main()
