from flask import Flask, request, jsonify
from ssl_certificate import generate_keys_and_certificate
from encryption import encrypt_message, decrypt_message
from flask_cors import CORS

app = Flask(__name__)

# Activer CORS
CORS(app)

# Génération des clés et certificat
private_key_pem, public_key_pem, cert_pem = generate_keys_and_certificate()


@app.route('/get_certificate', methods=['GET'])
def get_certificate():
    return jsonify({"certificate": cert_pem.decode()})


@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')
    if not message:
        return jsonify({"error": "Message manquant"}), 400
    ciphertext = encrypt_message(message, public_key_pem)
    return jsonify({"ciphertext": ciphertext.hex()})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    ciphertext = bytes.fromhex(data.get('ciphertext', ''))
    if not ciphertext:
        return jsonify({"error": "Ciphertext manquant"}), 400
    try:
        plaintext = decrypt_message(ciphertext, private_key_pem)
        return jsonify({"message": plaintext})
    except Exception as e:
        return jsonify({"error": f"Erreur lors du déchiffrement : {str(e)}"}), 400


if __name__ == '__main__':
    app.run(debug=True)
