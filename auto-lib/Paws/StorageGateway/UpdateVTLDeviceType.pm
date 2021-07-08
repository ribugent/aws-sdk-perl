
package Paws::StorageGateway::UpdateVTLDeviceType;
  use Moose;
  has DeviceType => (is => 'ro', isa => 'Str', required => 1);
  has VTLDeviceARN => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'UpdateVTLDeviceType');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::StorageGateway::UpdateVTLDeviceTypeOutput');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::StorageGateway::UpdateVTLDeviceType - Arguments for method UpdateVTLDeviceType on L<Paws::StorageGateway>

=head1 DESCRIPTION

This class represents the parameters used for calling the method UpdateVTLDeviceType on the
L<AWS Storage Gateway|Paws::StorageGateway> service. Use the attributes of this class
as arguments to method UpdateVTLDeviceType.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to UpdateVTLDeviceType.

=head1 SYNOPSIS

    my $storagegateway = Paws->service('StorageGateway');
    # To update a VTL device type
    # Updates the type of medium changer in a gateway-VTL after a gateway-VTL is
    # activated.
    my $UpdateVTLDeviceTypeOutput = $storagegateway->UpdateVTLDeviceType(
      'DeviceType'   => 'Medium Changer',
      'VTLDeviceARN' =>
'arn:aws:storagegateway:us-east-1:999999999999:gateway/sgw-12A3456B/device/AMZN_SGW-1FAD4876_MEDIACHANGER_00001'
    );

    # Results:
    my $VTLDeviceARN = $UpdateVTLDeviceTypeOutput->VTLDeviceARN;

    # Returns a L<Paws::StorageGateway::UpdateVTLDeviceTypeOutput> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/storagegateway/UpdateVTLDeviceType>

=head1 ATTRIBUTES


=head2 B<REQUIRED> DeviceType => Str

The type of medium changer you want to select.

Valid Values: C<STK-L700> | C<AWS-Gateway-VTL> | C<IBM-03584L32-0402>



=head2 B<REQUIRED> VTLDeviceARN => Str

The Amazon Resource Name (ARN) of the medium changer you want to
select.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method UpdateVTLDeviceType in L<Paws::StorageGateway>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

