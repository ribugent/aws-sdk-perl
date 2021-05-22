
package Paws::LicenseManager::AcceptGrant;
  use Moose;
  has GrantArn => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'AcceptGrant');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::LicenseManager::AcceptGrantResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::LicenseManager::AcceptGrant - Arguments for method AcceptGrant on L<Paws::LicenseManager>

=head1 DESCRIPTION

This class represents the parameters used for calling the method AcceptGrant on the
L<AWS License Manager|Paws::LicenseManager> service. Use the attributes of this class
as arguments to method AcceptGrant.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to AcceptGrant.

=head1 SYNOPSIS

    my $license-manager = Paws->service('LicenseManager');
    my $AcceptGrantResponse = $license -manager->AcceptGrant(
      GrantArn => 'MyArn',

    );

    # Results:
    my $GrantArn = $AcceptGrantResponse->GrantArn;
    my $Status   = $AcceptGrantResponse->Status;
    my $Version  = $AcceptGrantResponse->Version;

    # Returns a L<Paws::LicenseManager::AcceptGrantResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/license-manager/AcceptGrant>

=head1 ATTRIBUTES


=head2 B<REQUIRED> GrantArn => Str

Amazon Resource Name (ARN) of the grant.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method AcceptGrant in L<Paws::LicenseManager>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

