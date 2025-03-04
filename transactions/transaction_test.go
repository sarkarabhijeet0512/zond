package transactions

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"

	"github.com/theQRL/go-qrllib/dilithium"
	"github.com/theQRL/zond/protos"
)

func TestProtoToTransaction(t *testing.T) {
	masterDilithium := dilithium.New()
	masterDilithiumPK := masterDilithium.GetPK()

	networkID := uint64(1)
	fee := uint64(1)
	nonce := uint64(10)
	protoTx := &protos.Transaction{
		ChainId: networkID,
		Gas:     fee,
		Nonce:   nonce,
		Pk:      masterDilithiumPK[:],
	}

	_ = ProtoToTransaction(protoTx)
}

func TestGenerateTxHash(t *testing.T) {
	masterDilithiumPK, _ := hex.DecodeString("1998c3f1da2875b078cbb80dcfd96fb2d4249b1c1e4436ed42d26dd6341ca7873d5f42c9819fdc575e4316e933213b3a0de07a0de45893d92ba61686680ab706a48d30f3f869689777624762348f60cf68e7ad4d79734c370171f6543fc943cf8a2c41cee2b62691d8e6ab9c8001c155470eb072707fa442209f55ce9bee8d4741e8f6e6f3ce0ac9668f99dbc6937ffb6956a3635fa6b133229c4362ff98d8e301c079974503bef3d2d9b45e76294cbbdb3983fdcf0da1aec27c73c8166147d2ed3a74b87b544e17f8609370febcc6829fa8c863e8d87df62812dc743462d9a2aadd1cb51e2ada29f9451ae62cfd50cb27ffcd911a522a0ce757b30123ab0ae3277c6a9448f6763e1f73d026a2b85cca68ad848595207a9fd24e1848e6a10b6632017ae2c1bbe22478d5d2e83cea3a84b2f23ee5a0cff3e059070f3e4514a867f20d96be9017693d1dc1ff7b4c296bee5170689a7dca5725c29497efbfc514d677aba6ef05c795dce1b3a98decde4488e91d3009058e526a99bc5146f28cef5a7b4e8f7681c5f0c65e6afe7a0acb8884633760f7776a22cde28aa8d41d38f848a4d08b44aca29b5856a4316c3b002f7cae8ca1ce7f0e6ff13984afbdfe224a13b031bfcda49dc574edfd766284174bb0e1066eb28f536ebfddc07df7cfd73b7ee4ec10a4b20ca8a05ef1a13a9c9da3eb78722e8a37ff389805bb0e3896c8d97bacc406719edc9898edf6f3295f5ccc4ad884dca4e9a6a21da7d016de8caa9203e3a8e4a8b72cef8909e550828e928996724f4f1e6350893190d7ea9aa8304117093405b52f2e0fdee24fef40d87c9e0f94b0767fc7638493ca3c272ab0cee135c9274104aa50d0366688d24cf805a17ea31f36ad4ab48e8a22085d9189931e8188c0e7bc1b0b2ba6868badced85ee6e10574bb16d2e68df9323293556f194be6bc42eb4bc5961b3da428c577881aa64b90b390bbc31a0bd22036a602c9d672386cf9631564285d0dc75aa9de85f0a11e22b460b2c285d9819b27ef32b19d8d58ab04394409fb15d04a4378ad65f8efc509e2ecb26a862690a2627c010ceb78f35ab0e0e1adb5fd951f5dd8dce82c2a94c4dd02b40844c5f6e1a405fc276098717a5223ce2dd6a7ebc9376e2426f225451a162603a5dcd47dd7e891ba742b282533d20070a040d6c08e018a314a871d929de3a61867f32b0e719ef613bc1ac1f07af40c3ab47dd1e7e9093ca5bd72bc7e88175f8c3e81383966b0d0a8e898c88946c1bf9429ccfb85dbeedeebf2932c78e10996f2cc317a7ee2c9c3633dc689694349ab4d4bc2c7c0e749c8d674b38779805667a61238bb3ad44216606266eb12ebdc408b1ab1c88562fd77ff53eeb39caaf91bdf4bbee94ed1c8890c8748f40c91b206f5c8fc04c1ef5d064238b367544ceb4e8435a7834b1a238c3e2ebc37702ec44fe33a51f32c9725eebf884aebef889c15a416d523aa066ccebef0bd762111734650a76e83eead1035c36338ca67bf61979796540d3d3f61d29e93dc61c0e9de2d12580de66d080c79b354de2d9118d4326b021f940ba6b6fc09f18fd15d1329b1a50481f0d9befa1037dc136c8844c3c4070e78f0eba40b64b0a1b7ab8017ac2d21077d10d3c17747ae14241f1a67bcaaad0d8c9050aec3170d3098d13f23b6565fe821f1c8cb047149d990778defbc27fdd34528cdc8021e8cbe64e02247055411d30d46f29e9643a2ff35b350038047f40b233259533255d2865a4723e7c4ed83b695209a1c1b1c92b8a8c3f41647c7466b2e7922e0efc02af6aa28941233f688b7cb06ffd6e38a600d7e6a5e2db54f29298ee402ae801e02b6aa43e23fd79e62b5194f253c962c456bee7a6c6fae328a5fb4513bc998b74c95215d2d77f31223f6dddf2f1153bc55584207fb18fca620ac621e50b6e0c4f19ee485490310235b451c3c085f61c419a95d74e3086282066cb692ad51ce581b86c158022a5ce3b3bcc03fe8905d27621b3c58b5a2ec6434a7f5209512d5296968b937c2bc94c59899f435f996f4e90c027f092956465f0231ffe015677b92464cb19d5e")
	addrTo, _ := hex.DecodeString("2032d59e92326a17c976b8b1b47845b142b96b48")

	amount := uint64(30)
	fee := uint64(1)
	message := []byte("message")
	nonce := uint64(10)
	networkID := uint64(1)
	transfer := NewTransfer(networkID, addrTo[:], amount, 100000, big.NewInt(int64(fee)), big.NewInt(int64(0)), message, nonce, masterDilithiumPK[:])

	expectedHash, _ := hex.DecodeString("14efaf472130509ed0cf5b42d61017d69ca7824638540c2f54b257273ce2eef6")

	output := transfer.GenerateTxHash()
	if hex.EncodeToString(output.Bytes()) != hex.EncodeToString(expectedHash) {
		t.Errorf("expected transaction hash (%v), got (%v)", hex.EncodeToString(expectedHash), hex.EncodeToString(output.Bytes()))
	}
}
func TestTransaction_GasTipCap(t *testing.T) {
	type fields struct {
		pbData *protos.Transaction
	}
	tests := []struct {
		name   string
		fields fields
		want   *big.Int
	}{
		{
			name: "GasTipCap",
			fields: fields{
				pbData: &protos.Transaction{
					GasFeeTip: nil,
					GasFeeCap: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &Transaction{
				pbData: tt.fields.pbData,
			}
			if got := tx.GasTipCap(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Transaction.GasTipCap() = %v, want %v", got, tt.want)
			}
		})
	}
}
