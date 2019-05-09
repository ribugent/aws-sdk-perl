
package Paws::EC2::ModifyVpnConnection;
  use Moose;
  has DryRun => (is => 'ro', isa => 'Bool');
  has TransitGatewayId => (is => 'ro', isa => 'Str');
  has VpnConnectionId => (is => 'ro', isa => 'Str', required => 1);
  has VpnGatewayId => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ModifyVpnConnection');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::EC2::ModifyVpnConnectionResult');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::EC2::ModifyVpnConnection - Arguments for method ModifyVpnConnection on L<Paws::EC2>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ModifyVpnConnection on the
L<Amazon Elastic Compute Cloud|Paws::EC2> service. Use the attributes of this class
as arguments to method ModifyVpnConnection.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ModifyVpnConnection.

=head1 SYNOPSIS

    my $ec2 = Paws->service('EC2');
    my $ModifyVpnConnectionResult = $ec2->ModifyVpnConnection(
      VpnConnectionId  => 'MyString',
      DryRun           => 1,             # OPTIONAL
      TransitGatewayId => 'MyString',    # OPTIONAL
      VpnGatewayId     => 'MyString',    # OPTIONAL
    );

    # Results:
    my $VpnConnection = $ModifyVpnConnectionResult->VpnConnection;

    # Returns a L<Paws::EC2::ModifyVpnConnectionResult> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/ec2/ModifyVpnConnection>

=head1 ATTRIBUTES


=head2 DryRun => Bool





=head2 TransitGatewayId => Str





=head2 B<REQUIRED> VpnConnectionId => Str





=head2 VpnGatewayId => Str






=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ModifyVpnConnection in L<Paws::EC2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

