from pathlib import Path

class FTPHandler:
    def __init__(self,root):
        self.root = root
        self.current_dir = root
    
    def handle_cmd(self,cmd):
        cmd_split = cmd.strip().split()
        cmd_name = cmd_split[0].upper()
        args = cmd_split[1:]
        

    def handle_list(self,args):
        files = "\r\n".join(f.name for f in self.current_path.iterdir())
        return f"the files in the current dir are: \r\n{files}\r\n"

    def handle_cwd(self,args):
       new_path = (self.current_path / args[0]).resolve()   
       self.current_path = new_path
       return f" cwd to {self.current_path}." 
   
    def make_dir(self, args):
        dir_path = Path(args)
        try:
            dir_path.mkdir()
        except FileExistsError:
            return f"Directory {args} already exists."

        return "Directory {args} created successfully"
    def delete(self,args):
        pass
        
    