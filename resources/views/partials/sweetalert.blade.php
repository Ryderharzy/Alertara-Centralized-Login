<script>
    // Show success message if present
    @if(session('success'))
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: "{{ session('success') }}",
            confirmButtonColor: '#16a34a',
            confirmButtonText: 'OK'
        });
    @endif

    // Show error message if present
    @if(session('error'))
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: "{{ session('error') }}",
            confirmButtonColor: '#dc2626',
            confirmButtonText: 'OK'
        });
    @endif

    // Show info message if present
    @if(session('info'))
        Swal.fire({
            icon: 'info',
            title: 'Information',
            text: "{{ session('info') }}",
            confirmButtonColor: '#2f5f5e',
            confirmButtonText: 'OK'
        });
    @endif

    // Show warning message if present
    @if(session('warning'))
        Swal.fire({
            icon: 'warning',
            title: 'Warning',
            text: "{{ session('warning') }}",
            confirmButtonColor: '#dc2626',
            confirmButtonText: 'OK'
        });
    @endif

    // Show validation errors
    @if ($errors->any())
        @foreach ($errors->all() as $error)
            Swal.fire({
                icon: 'error',
                title: 'Validation Error',
                text: "{{ $error }}",
                confirmButtonColor: '#dc2626',
                confirmButtonText: 'OK'
            });
        @endforeach
    @endif
</script>
