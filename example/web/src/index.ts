const fReader = new FileReader();
fReader.onload = (event) => {
  const buf = event.target?.result;
  if (!buf) return;

  import("office-crypto-wasm")
    .then((w) =>
      w.decrypt(
        new Uint8Array(
          typeof buf === "string"
            ? new TextEncoder().encode(buf)
            : new Uint8Array(buf)
        ),
        "test"
      )
    )
    .then(console.log);
};

const handleInputChange = (event: Event) => {
  const target = event.target as HTMLInputElement;
  if (target.files && target.files.length > 0) {
    fReader.readAsArrayBuffer(target.files[0]);
  }
};

const input = () => {
  const inputElement = document.createElement("input");
  inputElement.name = "myfile";
  inputElement.type = "file";
  inputElement.addEventListener("change", handleInputChange);
  return inputElement;
};

document.body.appendChild(input());
