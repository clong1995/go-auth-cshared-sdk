package auth

import "testing"

func TestAccessID(t *testing.T) {
	type args struct {
		session int64
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "AccessID",
			args: args{session: 172565371008061442},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AccessID(tt.args.session)
			if err != nil {
				t.Errorf("AccessID() error = %v", err)
				return
			}
			t.Logf("AccessID() got = %v", got)
		})
	}
}
