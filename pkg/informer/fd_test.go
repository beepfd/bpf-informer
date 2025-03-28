package informer

import "testing"

func TestKernelHigher56_GetFD(t *testing.T) {
	type fields struct {
		PidFD PidFD
	}
	tests := []struct {
		name    string
		fields  fields
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KernelHigher56{
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
