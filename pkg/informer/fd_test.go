package informer

import "testing"

func TestKernelLower56_GetFD(t *testing.T) {
	type fields struct {
		PidFD PidFD
	}
	tests := []struct {
		name    string
		fields  fields
		want    int
		wantErr bool
	}{
		{
			name: "test",
			fields: fields{
				PidFD: PidFD{
					TargetPID: 1215083,
					TargetFD:  8,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KernelLower56{
				PidFD: tt.fields.PidFD,
			}
			got, err := k.GetFD()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetFD() got = %v, want %v", got, tt.want)
			}
		})
	}
}
