src_flag := if path_exists("../proto") == "true" { "--src ../proto" } else { "" }

default:
  tacplus build {{src_flag}}
